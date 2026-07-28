// ── Multi-server / reverse-proxy topology signals. Everything here is either read from headers
// already being collected elsewhere, or a handful of repeated plain GETs to the homepage (the same
// request a browser reload does) — no scanning beyond what's already in scope. ──

// Fires a few repeated requests to the same URL and compares response headers that commonly differ
// between backend instances behind a load balancer (Server, X-Powered-By, Via, X-Served-By,
// X-Request-Id-style instance identifiers). Consistent headers don't prove a single server (a
// well-configured fleet looks identical on purpose), but *inconsistent* headers are a solid signal
// of multiple distinct backends answering.
const INSTANCE_HEADER_NAMES = ['server', 'x-powered-by', 'via', 'x-served-by', 'x-backend-server', 'x-instance-id'];

export async function checkResponseConsistency(url, { attempts = 4, delayMs = 300, timeoutMs = 8000 } = {}) {
  const samples = [];
  for (let i = 0; i < attempts; i++) {
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(url, { headers: { 'user-agent': 'Universal-Security-Audit', 'cache-control': 'no-cache' }, signal: controller.signal });
      clearTimeout(t);
      const sample = {};
      for (const name of INSTANCE_HEADER_NAMES) sample[name] = res.headers.get(name) || '';
      samples.push(sample);
    } catch { /* one failed attempt doesn't invalidate the others */ }
    if (i < attempts - 1 && delayMs) await new Promise((r) => setTimeout(r, delayMs));
  }
  if (samples.length < 2) return { checked: false, samples };

  const variations = [];
  for (const name of INSTANCE_HEADER_NAMES) {
    const values = new Set(samples.map((s) => s[name]).filter(Boolean));
    if (values.size > 1) variations.push({ header: name, values: [...values] });
  }
  return { checked: true, attempts: samples.length, variations, multiServerLikely: variations.length > 0 };
}

// A single response can hint at a reverse proxy: a `Via` header is the standard, explicit signal;
// seeing both a CDN/edge signal (Cloudflare, Fastly, etc.) AND an origin-server signal (nginx/Apache
// in the same Server header, or a distinct one) in one response also implies a proxy layer in front
// of an origin, even without a Via header (many CDNs don't add one by default).
export function checkReverseProxyIndicators(headers = {}, hostingSignals = []) {
  const get = (name) => String((headers.get ? headers.get(name) : headers[name]) || '');
  const via = get('via');
  const cdnProviders = new Set(['Cloudflare', 'Vercel', 'Netlify', 'Fastly', 'AWS CloudFront', 'GitHub Pages']);
  const originProviders = new Set(['Apache (origin server)', 'nginx (origin server)']);
  const hasCdnSignal = hostingSignals.some((h) => cdnProviders.has(h.provider));
  const hasOriginSignal = hostingSignals.some((h) => originProviders.has(h.provider));
  const likelyProxied = !!via || (hasCdnSignal && hasOriginSignal);
  return {
    hasVia: !!via,
    viaValue: via || null,
    hasCdnSignal,
    hasOriginSignal,
    likelyProxied,
    note: likelyProxied
      ? `Traffic passes through a reverse proxy/CDN before reaching the origin${via ? ` (Via: ${via})` : hasCdnSignal && hasOriginSignal ? ` (${[...hostingSignals.map((h) => h.provider)].join(' + ')})` : ''}.`
      : 'No reverse-proxy indicator found in this response (many proxies are transparent and won\'t show up this way).',
  };
}

// More than one A record with no recognized CDN in front is a reasonable hint of DNS-level load
// balancing across the site's own servers (CDNs also return multiple IPs, but those are edge nodes,
// not the client's own infrastructure — already accounted for separately via hostingSignals).
export function checkDnsLoadBalancingHint(dnsRecords = {}, hostingSignals = []) {
  const aCount = (dnsRecords.a || []).length;
  const hasCdn = hostingSignals.some((h) => ['Cloudflare', 'Vercel', 'Netlify', 'Fastly', 'AWS CloudFront'].includes(h.provider));
  return {
    multipleARecords: aCount > 1,
    likelyOwnLoadBalancing: aCount > 1 && !hasCdn,
    aRecordCount: aCount,
  };
}
