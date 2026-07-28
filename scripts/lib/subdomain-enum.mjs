// ── Passive subdomain enumeration via crt.sh (certificate-transparency log search). Purely reads
// public CT log data — no active DNS brute force. Optional liveness check is a single HEAD request
// per discovered host, capped by --intensity. ──
import dns from 'node:dns/promises';

// crt.sh is a free community service that frequently returns 502/503 under load or takes 10-20s+ to
// respond — this is normal for it, not a sign anything is wrong. Retry with backoff before giving up.
export async function enumerateSubdomainsCrtSh(domain, { timeoutMs = 20000, retries = 2 } = {}) {
  let lastError = null;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
        headers: { 'user-agent': 'Universal-Security-Audit', accept: 'application/json' },
        signal: controller.signal,
      });
      clearTimeout(t);
      if (!res.ok) { lastError = `HTTP ${res.status}`; }
      else {
        const data = await res.json().catch(() => []);
        const names = new Set();
        for (const entry of data) {
          for (const raw of String(entry.name_value || '').split('\n')) {
            const name = raw.trim().toLowerCase().replace(/^\*\./, '');
            if (name.endsWith(domain) && name !== domain && !name.includes(' ')) names.add(name);
          }
        }
        return { checked: true, subdomains: [...names].sort() };
      }
    } catch (e) {
      clearTimeout(t);
      lastError = String(e?.message || e);
    }
    if (attempt < retries) await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
  }
  return { checked: false, error: lastError, subdomains: [] };
}

export async function checkLiveness(hostnames = [], { limit = 15, concurrency = 8, timeoutMs = 5000 } = {}) {
  const queue = hostnames.slice(0, limit);
  const results = [];
  async function worker() {
    while (queue.length) {
      const host = queue.shift();
      let resolved = false;
      try { await dns.resolve(host); resolved = true; } catch {}
      if (!resolved) { results.push({ host, alive: false, resolved: false }); continue; }
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetch(`https://${host}/`, { method: 'HEAD', redirect: 'manual', signal: controller.signal, headers: { 'user-agent': 'Universal-Security-Audit' } });
        clearTimeout(timer);
        results.push({ host, alive: true, resolved: true, status: res.status });
      } catch {
        results.push({ host, alive: false, resolved: true });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length || 1) }, worker));
  return results;
}
