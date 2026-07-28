// ── Official wordpress.org Plugin/Theme Directory API — used to determine whether an installed
// version is outdated. This replaces scraping wp-admin's "View version X details" update-nag markup
// (which is UI text, not a stable contract) with a public, versioned API endpoint. ──

async function safeFetchJson(url, { timeoutMs = 8000 } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers: { 'user-agent': 'Universal-Security-Audit' }, signal: controller.signal });
    clearTimeout(t);
    if (!res.ok) return null;
    return await res.json();
  } catch { clearTimeout(t); return null; }
}

export async function lookupLatestPluginVersion(slug) {
  const data = await safeFetchJson(`https://api.wordpress.org/plugins/info/1.0/${encodeURIComponent(slug)}.json`);
  if (!data || !data.version) return null;
  return { latestVersion: data.version, name: data.name, lastUpdated: data.last_updated || null, activeInstalls: data.active_installs ?? null };
}

export async function lookupLatestThemeVersion(slug) {
  const url = `https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=${encodeURIComponent(slug)}`;
  const data = await safeFetchJson(url);
  if (!data || !data.version) return null;
  return { latestVersion: data.version, name: data.name };
}

function semverLt(a, b) {
  const pa = String(a || '0').split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b || '0').split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

// Cross-references a list of {slug, version} against the plugin directory API, with modest
// concurrency since this is one HTTP call per installed plugin/theme.
export async function checkOutdatedAgainstDirectory(items, lookupFn, { concurrency = 4 } = {}) {
  const results = [];
  const queue = [...items];
  async function worker() {
    while (queue.length) {
      const item = queue.shift();
      const info = await lookupFn(item.slug);
      if (info && item.version) {
        results.push({ ...item, latestVersion: info.latestVersion, outdated: semverLt(item.version, info.latestVersion) });
      } else {
        results.push({ ...item, latestVersion: info?.latestVersion ?? null, outdated: null });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length || 1) }, worker));
  return results;
}
