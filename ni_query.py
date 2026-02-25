#!/usr/bin/env python3
"""
NI Server Browser - GitHub Actions query script

Flow:
  1. Fetch TW master list (IP:PORT pairs)
  2. For each endpoint, try HTTP first (works for NA/CN)
  3. If HTTP fails, try UDP query (needed for EU servers)
     - First: direct Len=31 info request (no handshake)
     - Fallback: full 2-step ping → ack → info request
  4. [BOTH] servers: log HTTP plaintext + UDP hex for known-plaintext analysis
  5. [UDP?] servers: keep with placeholder name so they appear in the output
  6. Write ni_servers.json + ni_debug.txt
"""

import socket
import struct
import random
import concurrent.futures
import json
import re
import sys
import requests
from datetime import datetime, timezone

TW_MASTER_URL = "https://warbandmain.taleworlds.com/handlerservers.ashx?type=list"
HTTP_TIMEOUT  = 4   # seconds
UDP_TIMEOUT   = 4   # seconds per attempt
MAX_ENDPOINTS = 600

debug_lines = []

def dprint(*args):
    msg = " ".join(str(a) for a in args)
    print(msg)
    debug_lines.append(msg)
    sys.stdout.flush()


# ─────────────────────── helpers ────────────────────────────────────

def xml_tag(text, tag):
    m = re.search(fr'<{tag}[^>]*>([^<]*)</{tag}>', text, re.I)
    return m.group(1).strip() if m else None


# ─────────────────────── HTTP probe ─────────────────────────────────

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


# ─────────────────────── UDP query ──────────────────────────────────

def _make_info_request(sid_hi, sid_lo, tok_hi=0xEC, tok_lo=0xB2):
    """Build the 31-byte Warband server info request."""
    return bytes([0x1F, sid_hi, sid_lo, tok_hi, tok_lo,
                  0x40, 0x00, 0x24, 0x09, 0x00, 0xF3, 0x5E,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x80, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x04, 0x00])


def udp_query(ip, port):
    """
    Try to get Warband server info via UDP.

    Attempts two strategies:
      A) Direct: send Len=31 info request without a prior handshake
      B) 2-step: ping (Len=6) → ack (Len=6) → info request (Len=31)

    Returns raw response bytes or None.
    """
    sid_hi = random.randint(0, 255)
    sid_lo = random.randint(0, 255)

    # ── Strategy A: direct info request (no ping) ──
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        info = _make_info_request(sid_hi, sid_lo)
        sock.sendto(info, (ip, port))
        try:
            resp, _ = sock.recvfrom(2048)
            if len(resp) > 20:
                return resp, 'direct'
        except socket.timeout:
            pass
    except Exception:
        pass
    finally:
        sock.close()

    # ── Strategy B: full 2-step handshake ──
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)

        ping = bytes([0x06, sid_hi, sid_lo, 0x00, 0x00, 0x01])
        sock.sendto(ping, (ip, port))

        try:
            ack, _ = sock.recvfrom(256)
        except socket.timeout:
            return None, 'no_ack'

        tok_hi = ack[3] if len(ack) > 3 else 0xEC
        tok_lo = ack[4] if len(ack) > 4 else 0xB2

        info = _make_info_request(sid_hi, sid_lo, tok_hi, tok_lo)
        sock.sendto(info, (ip, port))

        try:
            resp, _ = sock.recvfrom(2048)
            if len(resp) > 20:
                return resp, '2step'
        except socket.timeout:
            return None, 'no_resp'

    except Exception as e:
        return None, f'err:{e}'
    finally:
        sock.close()

    return None, 'failed'


# ─────────────────────── UDP decode ─────────────────────────────────

def try_xor_find_ni(segment):
    """Try all 256 XOR keys on a null-terminated segment; return decoded string if NI_ found."""
    for key in range(256):
        decoded = bytes(b ^ key for b in segment)
        try:
            s = decoded.decode('ascii')
            if s.startswith('NI_') and all(32 <= ord(c) < 127 for c in s):
                return s
        except Exception:
            pass
    return None


def decode_udp_response(data, ip, port):
    """
    Best-effort decode of the Warband binary server info response.

    String section: bytes 0-84 (null-delimited, XOR-obfuscated, cipher unknown)
    Integer section: bytes 85+ (4-byte LE ints: game settings)

    From one captured 174-byte packet (116.202.115.104:21261):
      int[6]=128 → likely max_players
      int[8]=2   → likely active_players
      (UNVERIFIED — [BOTH] cross-ref will confirm)
    """
    if not data or len(data) < 20:
        return None

    # ── Try to find server name via XOR brute-force on each null-terminated segment ──
    name = None
    seg_start = 12
    for i in range(seg_start, min(85, len(data))):
        if data[i] == 0:
            seg = data[seg_start:i]
            if len(seg) >= 4:
                candidate = try_xor_find_ni(seg)
                if candidate:
                    name = candidate
                    break
            seg_start = i + 1

    # ── Extract integers from byte 85 onward ──
    int_sec = data[85:] if len(data) > 85 else b''
    ints = []
    for off in range(0, len(int_sec) - 3, 4):
        ints.append(struct.unpack_from('<I', int_sec, off)[0])

    max_pl = ints[6] if len(ints) > 6 else 0
    cur_pl = ints[8] if len(ints) > 8 else 0
    if max_pl > 500 or cur_pl > max_pl:
        max_pl = 0
        cur_pl = 0

    return {
        'name':      name,
        'players':   cur_pl,
        'max':       max_pl,
        'ip':        ip,
        'port':      port,
        'source':    'udp',
        '_udp_hex':  data.hex(),
        '_udp_ints': ints[:24],
    }


# ─────────────────────── per-server probe ───────────────────────────

def probe_server(ip, port):
    http = http_probe(ip, port)
    udp_data, udp_method = udp_query(ip, port)

    if http and udp_data:
        dec = decode_udp_response(udp_data, ip, port)
        dprint(f"[BOTH] {ip}:{port}  method={udp_method}")
        dprint(f"  HTTP  name={http['name']!r} module={http['module']!r} "
               f"map={http['map']!r} players={http['players']} max={http['max']}")
        dprint(f"  UDP   name_guess={dec['name'] if dec else '?'}  "
               f"players_guess={dec['players'] if dec else '?'}  "
               f"max_guess={dec['max'] if dec else '?'}")
        dprint(f"  UDP   full_hex={udp_data.hex()}")
        dprint(f"  UDP   ints={dec['_udp_ints'] if dec else []}")
        return http

    if http:
        return http

    if udp_data:
        dec = decode_udp_response(udp_data, ip, port)
        if dec:
            placeholder = dec['name'] or f"NI_EU_???_{ip}:{port}"
            dec['name'] = placeholder
            if dec['name'].startswith('NI_'):
                dprint(f"[UDP ] {ip}:{port}  method={udp_method}  "
                       f"name={dec['name']!r}  players={dec['players']}  max={dec['max']}")
            else:
                dprint(f"[UDP?] {ip}:{port}  method={udp_method}  name=UNKNOWN  "
                       f"players={dec['players']}  max={dec['max']}")
                dprint(f"  full_hex={udp_data.hex()}")
                dprint(f"  ints={dec['_udp_ints']}")
            return dec

    # Both failed — log why
    if udp_method not in ('no_ack', 'no_resp', 'failed') and udp_method:
        dprint(f"[MISS] {ip}:{port}  udp={udp_method}")

    return None


# ─────────────────────────── main ───────────────────────────────────

def main():
    dprint(f"=== NI Server Browser run at {datetime.now(timezone.utc).isoformat()} ===")

    dprint("Fetching TW master list…")
    try:
        resp = requests.get(TW_MASTER_URL, timeout=10)
        endpoints = [e.strip() for e in resp.text.split('|')
                     if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$', e.strip())]
        endpoints = endpoints[:MAX_ENDPOINTS]
        dprint(f"Got {len(endpoints)} endpoints from TW master list")

        # Log any 116.202.115.x entries (known NI EU host)
        eu_eps = [e for e in endpoints if e.startswith('116.202.115.')]
        dprint(f"EU endpoints (116.202.115.x) in TW list: {eu_eps or 'NONE'}")

    except Exception as e:
        dprint(f"Failed to fetch TW master list: {e}")
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
                dprint(f"  Progress: {done}/{len(endpoints)}")
            try:
                r = fut.result()
                # Keep server if it has any name at all (including placeholders)
                if r and r.get('name'):
                    results.append(r)
            except Exception:
                pass

    # Strip internal analysis fields, write JSON
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

    dprint(f"\nTotal servers found: {len(clean)}")
    for s in clean:
        dprint(f"  {s['name']}: {s['players']}/{s['max']}  [{s.get('source','?')}]")

    with open('ni_servers.json', 'w') as f:
        json.dump(clean, f, indent=2)
    dprint("Written ni_servers.json")

    with open('ni_debug.txt', 'w') as f:
        f.write("\n".join(debug_lines))
    dprint("Written ni_debug.txt")


if __name__ == '__main__':
    main()
