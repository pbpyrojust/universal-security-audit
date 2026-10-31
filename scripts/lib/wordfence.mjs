// ── Wordfence Intelligence: known WordPress core/plugin/theme vulnerabilities ──
// Free for commercial use with attribution; each user brings their own API key (wordfence.com →
// Integrations). The feed is one ~160 MB JSON object, and the key's download limit is small and
// unpublished, so it's fetched at most once a day and kept as a compact index (slug → ranges) in
// the user's cache folder; later runs read only the index. Only used for sites detected as
// WordPress, and only when a key is given.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const FEED = 'https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production';
const MAX_AGE_MS = 24 * 3600_000;

export const WORDFENCE_ATTRIBUTION = 'Vulnerability data: Wordfence Intelligence (https://www.wordfence.com/threat-intel/). Copyright Defiant Inc., used under the Wordfence Intelligence license (https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/).';

function cacheFile() {
  const base = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  return path.join(base, 'universal-security-audit', 'wordfence-index.json');
}

/** -1, 0 or 1, comparing dotted versions number by number ("6.10.2" > "6.9.10"). */
export function compareVersions(a, b) {
  const pa = String(a).split(/[.\-+]/).map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(/[.\-+]/).map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

export function isAffected(version, ranges) {
  return ranges.some((r) => {
    const above = r.from === '*' || (r.fi ? compareVersions(version, r.from) >= 0 : compareVersions(version, r.from) > 0);
    const below = r.to === '*' || (r.ti ? compareVersions(version, r.to) <= 0 : compareVersions(version, r.to) < 0);
    return above && below;
  });
}

/** Feed records → { "plugin:slug": [{ id, title, cve, rating, score, ranges, patched, url }] }. Exported for tests. */
export function buildIndex(feed) {
  const index = {};
  for (const [id, v] of Object.entries(feed)) {
    if (v.informational) continue;
    for (const s of v.software ?? []) {
      const kind = ['core', 'plugin', 'theme'].includes(s.type) ? s.type : null;
      const slug = kind === 'core' ? 'wordpress' : String(s.slug ?? '').toLowerCase();
      if (!kind || !slug) continue;
      const ranges = Object.values(s.affected_versions ?? {}).map((r) => ({ from: String(r.from_version ?? '*'), fi: r.from_inclusive !== false, to: String(r.to_version ?? '*'), ti: r.to_inclusive !== false }));
      if (!ranges.length) continue;
      const key = `${kind}:${slug}`;
      const list = (index[key] ??= []);
      const same = list.find((x) => x.id === id);
      if (same) {
        // Core vulnerabilities list WordPress once per release branch.
        same.ranges.push(...ranges);
        same.patched = [...new Set([...same.patched, ...(s.patched_versions ?? []).map(String)])];
        continue;
      }
      list.push({
        id,
        title: String(v.title ?? ''),
        cve: v.cve ?? null,
        rating: v.cvss?.rating ? String(v.cvss.rating).toLowerCase() : null,
        score: v.cvss?.score ?? null,
        ranges,
        patched: (s.patched_versions ?? []).map(String),
        url: (v.references ?? []).find((u) => /wordfence\.com/.test(u)) ?? `https://www.wordfence.com/threat-intel/vulnerabilities/id/${id}`,
      });
    }
  }
  return index;
}

/** The cached index, refreshed when older than a day. Returns { index, error }. */
export async function loadIndex(apiKey, { file = cacheFile(), now = Date.now() } = {}) {
  let cached = null;
  try {
    const stat = fs.statSync(file);
    cached = { index: JSON.parse(fs.readFileSync(file, 'utf8')), fresh: now - stat.mtimeMs < MAX_AGE_MS };
  } catch {}
  if (cached?.fresh) return { index: cached.index, error: null };
  try {
    const res = await fetch(FEED, { headers: { Authorization: `Bearer ${apiKey}` }, signal: AbortSignal.timeout(300_000) });
    if (!res.ok) {
      const why = res.status === 401 ? 'Wordfence refused the API key (check WORDFENCE_API_KEY)' : res.status === 429 ? 'the Wordfence key\'s download limit was reached; try again in a few hours' : `Wordfence answered HTTP ${res.status}`;
      // An older copy is better than nothing.
      return cached ? { index: cached.index, error: `${why}; used the copy from ${new Date(fs.statSync(file).mtimeMs).toISOString().slice(0, 10)}` } : { index: null, error: why };
    }
    const index = buildIndex(await res.json());
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(index));
    return { index, error: null };
  } catch (e) {
    return cached ? { index: cached.index, error: `couldn't refresh the Wordfence feed (${e?.message || e}); used the cached copy` } : { index: null, error: `couldn't download the Wordfence feed (${e?.message || e})` };
  }
}

/** Vulnerabilities affecting one component at this exact version, each with the first fixed version above it. */
export function lookup(index, kind, slug, version) {
  if (!index || !version) return [];
  return (index[`${kind}:${String(slug).toLowerCase()}`] ?? [])
    .filter((v) => isAffected(version, v.ranges))
    .map((v) => ({ ...v, fixedIn: v.patched.filter((p) => compareVersions(p, version) > 0).sort(compareVersions)[0] ?? null }));
}

/** Finding severity from Wordfence's rating, or the CVSS score. */
export function severityOf(v) {
  if (['critical', 'high', 'medium', 'low'].includes(v.rating)) return v.rating;
  const s = Number(v.score);
  return s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : 'low';
}
