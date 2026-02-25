// Cloudflare Worker: NI Server Browser
// Fetches the TaleWorlds master list, probes all IPs via HTTP in parallel,
// supplements with mnbcentral, caches 30s, returns JSON.

const TW_MASTER_URL = 'https://warbandmain.taleworlds.com/handlerservers.ashx?type=list';
const MNB_MIN_URL = 'http://www.mnbcentral.net/min';
const CACHE_TTL = 30;        // seconds
const HTTP_TIMEOUT_MS = 5000; // per server probe
const MAX_ENDPOINTS = 600;   // safety cap on TW master list size

function extractXmlTag(text, tag) {
  const m = text.match(new RegExp('<' + tag + '[^>]*>([^<]*)</' + tag + '>', 'i'));
  return m ? m[1].trim() : null;
}

async function fetchWithTimeout(url, timeoutMs) {
  try {
    const resp = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    return await resp.text();
  } catch {
    return null;
  }
}

async function probeHttpEndpoint(ip, port) {
  const text = await fetchWithTimeout('http://' + ip + ':' + port + '/', HTTP_TIMEOUT_MS);
  if (!text) return null;
  const name = extractXmlTag(text, 'Name');
  if (!name || !name.startsWith('NI_')) return null;
  return {
    name,
    module:  extractXmlTag(text, 'ModuleName') || '',
    map:     extractXmlTag(text, 'MapName') || '',
    players: parseInt(extractXmlTag(text, 'NumberOfActivePlayers') || '0') || 0,
    max:     parseInt(extractXmlTag(text, 'MaxNumberOfPlayers') || '0') || 0,
    source:  'http',
  };
}

async function fetchMnbCentral() {
  const text = await fetchWithTimeout(MNB_MIN_URL, 10000);
  if (!text) return [];
  const servers = [];
  for (const line of text.split(/<br\s*\/?>/i)) {
    const parts = line.trim().split(',');
    if (parts.length < 7) continue;
    const name = (parts[0] || '').trim();
    if (!name.startsWith('NI_')) continue;
    servers.push({
      name,
      module:  (parts[1] || '').trim(),
      map:     (parts[3] || '').trim(),
      players: parseInt((parts[5] || '0').replace(/,/g, '')) || 0,
      max:     parseInt((parts[6] || '0').replace(/,/g, '')) || 0,
      source:  'mnbcentral',
    });
  }
  return servers;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
        },
      });
    }

    // Cache check
    const cache = caches.default;
    const cacheKey = new Request('https://ni-server-browser-cache/v1');
    const cached = await cache.match(cacheKey);
    if (cached) {
      const r = new Response(cached.body, cached);
      r.headers.set('X-Cache', 'HIT');
      return r;
    }

    // Fetch TW master list and mnbcentral in parallel
    const [twText, mnbServers] = await Promise.all([
      fetchWithTimeout(TW_MASTER_URL, 10000),
      fetchMnbCentral(),
    ]);

    // Parse IP:PORT list from TW master
    let endpoints = [];
    if (twText) {
      endpoints = twText
        .split('|')
        .map(e => e.trim())
        .filter(e => /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$/.test(e))
        .slice(0, MAX_ENDPOINTS);
    }

    // Probe all endpoints via HTTP in parallel
    const probeResults = await Promise.allSettled(
      endpoints.map(ep => {
        const [ip, port] = ep.split(':');
        return probeHttpEndpoint(ip, port);
      })
    );
    const httpServers = probeResults
      .filter(r => r.status === 'fulfilled' && r.value !== null)
      .map(r => r.value);

    // Merge: HTTP data takes priority over mnbcentral for same server name
    const merged = new Map();
    for (const s of mnbServers) merged.set(s.name, s);
    for (const s of httpServers) merged.set(s.name, s);

    const result = Array.from(merged.values()).sort((a, b) => a.name.localeCompare(b.name));

    const response = new Response(JSON.stringify(result), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=' + CACHE_TTL,
        'X-Cache': 'MISS',
        'X-Endpoints-Probed': String(endpoints.length),
        'X-HTTP-Found': String(httpServers.length),
        'X-MNB-Found': String(mnbServers.length),
      },
    });

    ctx.waitUntil(cache.put(cacheKey, response.clone()));
    return response;
  },
};
