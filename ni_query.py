#!/usr/bin/env python3
"""
NI Server Browser - GitHub Actions query script

Flow:
  1. Fetch TW master list (IP:PORT pairs)
  2. For each endpoint, try HTTP first (works for NA/CN)
  3. If HTTP fails, send 2-step UDP query (needed for EU)
  4. For servers responding to BOTH: dump UDP hex + HTTP plaintext
     for known-plaintext analysis of the binary encoding
  5. Write ni_servers.json
"""

import socket
import struct
import random
import concurrent.futures
import json
import re
import sys
import requests

TW_MASTER_URL = "https://warbandmain.taleworlds.com/handlerservers.ashx?type=list"
HTTP_TIMEOUT  = 4   # seconds
UDP_TIMEOUT   = 3   # seconds
MAX_ENDPOINTS = 600

# ───────────────────────────── helpers ──────────────────────────────

def xml_tag(text, tag):
    m = re.search(fr'<{tag}[^>]*>([^<]*)</{tag}>', text, re.I)
    return m.group(1).strip() if m else None


# ───────────────────────────── HTTP probe ───────────────────────────

def http_probe(ip, port):
    try:
        r = requests.get(f"http://{ip}:{port}/", timeout=HTTP_TIMEOUT)
        name = xml_tag(r.text, 'Name')
        if not name or not name.startswith('NI_'):
            return None
        return {
            'name':    name,
            'module':  xml_tag(r.text, 'ModuleName') or '',
            'map':     xml_tag(r.text, 'MapName') or '',
            'players': int(xml_tag(r.text, 'NumberOfActivePlayers') or '0'),
            'max':     int(xml_tag(r.text, 'MaxNumberOfPlayers') or '0'),
            'source':  'http',
        }
    except Exception:
        return None


# ───────────────────────────── UDP query ────────────────────────────

def udp_query(ip, port):
    """
    2-step Warband server info query over UDP.

    Protocol (captured via Wireshark):
      1. Client → Server: 6 bytes  [0x06, sid_hi, sid_lo, 0x00, 0x00, 0x01]
      2. Server → Client: 6 bytes  (ack; bytes 3-4 may carry a server token)
      3. Client → Server: 31 bytes [0x1F, sid_hi, sid_lo, tok_hi, tok_lo, ...]
      4. Server → Client: 163-177 bytes (binary server info)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UDP_TIMEOUT)
    try:
        sid_hi = random.randint(0, 255)
        sid_lo = random.randint(0, 255)

        # ── Step 1: ping ──
        ping = bytes([0x06, sid_hi, sid_lo, 0x00, 0x00, 0x01])
        sock.sendto(ping, (ip, port))

        # ── Step 2: ack ──
        try:
            ack, _ = sock.recvfrom(256)
        except socket.timeout:
            return None
        if len(ack) < 6:
            return None

        # Extract server token from ack bytes 3-4 (fallback to captured values)
        tok_hi = ack[3] if len(ack) > 3 else 0xEC
        tok_lo = ack[4] if len(ack) > 4 else 0xB2

        # ── Step 3: info request (31 bytes) ──
        info = bytes([0x1F, sid_hi, sid_lo, tok_hi, tok_lo,
                      0x40, 0x00, 0x24, 0x09, 0x00, 0xF3, 0x5E,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x80, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x04, 0x00])
        sock.sendto(info, (ip, port))

        # ── Step 4: server info response ──
        try:
            resp, _ = sock.recvfrom(2048)
        except socket.timeout:
            return None

        return resp

    except Exception:
        return None
    finally:
        sock.close()


# ───────────────────────── UDP decode (best-effort) ─────────────────

def try_xor_find_ni(data, start, end):
    """
    Try all 256 single-byte XOR keys on data[start:null_end].
    Returns decoded string if it starts with 'NI_' and is all printable ASCII.
    """
    for null_pos in range(start, min(end, len(data))):
        if data[null_pos] == 0:
            seg = data[start:null_pos]
            if len(seg) < 4:
                continue
            for key in range(256):
                decoded = bytes(b ^ key for b in seg)
                try:
                    s = decoded.decode('ascii')
                    if s.startswith('NI_') and all(32 <= ord(c) < 127 for c in s):
                        return s
                except Exception:
                    pass
            break
    return None


def decode_udp_response(data, ip, port):
    """
    Best-effort decode of the Warband binary server info response.

    Known structure (from one captured packet, 174 bytes):
      Bytes  0-84:  obfuscated string section (null-delimited, encoded)
      Bytes 85+:   4-byte LE integers (game settings / stats)

    From the one captured packet:
      int[6]  (bytes 109-112) = 128  → max_players (needs verification)
      int[8]  (bytes 117-120) = 2    → active_players (needs verification)

    The string encoding key is not a simple single-byte XOR across the whole
    packet; the cross-reference run (servers responding to both HTTP and UDP)
    will reveal the actual encoding. Until then we brute-force XOR segment by
    segment looking for the 'NI_' prefix.
    """
    if not data or len(data) < 20:
        return None

    # ── Try to find the server name (XOR brute-force on null-delimited segments) ──
    name = None
    seg_start = 12   # first string likely starts around byte 12
    for i in range(seg_start, min(85, len(data))):
        if data[i] == 0:
            candidate = try_xor_find_ni(data, seg_start, i)
            if candidate:
                name = candidate
                break
            seg_start = i + 1

    # ── Extract integers from byte 85 onward ──
    int_sec = data[85:] if len(data) > 85 else b''
    ints = []
    for off in range(0, len(int_sec) - 3, 4):
        ints.append(struct.unpack_from('<I', int_sec, off)[0])

    # Heuristic guesses based on one captured packet
    # int[6]=128 (max_players), int[8]=2 (active_players)
    # These are UNVERIFIED — will be corrected once cross-reference runs.
    max_pl  = ints[6] if len(ints) > 6 else 0
    cur_pl  = ints[8] if len(ints) > 8 else 0

    # Sanity-check: reject nonsensical values
    if max_pl > 500 or cur_pl > max_pl:
        max_pl = 0
        cur_pl = 0

    return {
        'name':     name,
        'players':  cur_pl,
        'max':      max_pl,
        'ip':       ip,
        'port':     port,
        'source':   'udp',
        # Include first 92 bytes of raw response for offline analysis
        '_udp_hex': data[:92].hex(),
        '_udp_ints': ints[:20],
    }


# ───────────────────────── per-server probe ─────────────────────────

def probe_server(ip, port):
    http = http_probe(ip, port)
    udp  = udp_query(ip, port)

    if http and udp:
        # ── KNOWN-PLAINTEXT: log everything for encoding analysis ──
        dec = decode_udp_response(udp, ip, port)
        print(f"[BOTH] {ip}:{port}")
        print(f"  HTTP  name={http['name']!r} module={http['module']!r} "
              f"map={http['map']!r} players={http['players']} max={http['max']}")
        print(f"  UDP   name_guess={dec['name'] if dec else '?'}  "
              f"players_guess={dec['players'] if dec else '?'}  "
              f"max_guess={dec['max'] if dec else '?'}")
        print(f"  UDP   hex={udp[:92].hex()}")
        print(f"  UDP   ints={dec['_udp_ints'] if dec else []}")
        sys.stdout.flush()
        return http

    if http:
        return http

    if udp:
        dec = decode_udp_response(udp, ip, port)
        if dec:
            if dec['name']:
                print(f"[UDP ] {ip}:{port} -> name={dec['name']!r} "
                      f"players={dec['players']} max={dec['max']}")
            else:
                print(f"[UDP?] {ip}:{port} -> name=UNKNOWN "
                      f"players={dec['players']} max={dec['max']}  "
                      f"hex={dec['_udp_hex']}")
            sys.stdout.flush()
        return dec

    return None


# ─────────────────────────────── main ───────────────────────────────

def main():
    print("Fetching TW master list…")
    try:
        resp = requests.get(TW_MASTER_URL, timeout=10)
        endpoints = [e.strip() for e in resp.text.split('|')
                     if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', e.strip())]
        endpoints = endpoints[:MAX_ENDPOINTS]
        print(f"Got {len(endpoints)} endpoints from TW master list")
    except Exception as e:
        print(f"Failed to fetch TW master list: {e}")
        endpoints = []

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as exe:
        futures = {
            exe.submit(probe_server, ep.split(':')[0], int(ep.split(':')[1])): ep
            for ep in endpoints
        }
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            if done % 100 == 0:
                print(f"  Progress: {done}/{len(endpoints)}")
                sys.stdout.flush()
            try:
                r = fut.result()
                if r and r.get('name') and r['name'].startswith('NI_'):
                    results.append(r)
            except Exception:
                pass

    # Strip internal analysis fields before writing JSON
    clean = []
    for r in results:
        clean.append({
            'name':    r.get('name', ''),
            'module':  r.get('module', ''),
            'map':     r.get('map', ''),
            'players': r.get('players', 0),
            'max':     r.get('max', 0),
        })
    clean.sort(key=lambda x: x['name'])

    print(f"\nTotal NI servers: {len(clean)}")
    for s in clean:
        print(f"  {s['name']}: {s['players']}/{s['max']}")

    with open('ni_servers.json', 'w') as f:
        json.dump(clean, f, indent=2)
    print("Written ni_servers.json")


if __name__ == '__main__':
    main()
