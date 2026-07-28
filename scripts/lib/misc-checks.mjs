// ── CORS misconfig, mixed-content, and public AI/SEO-crawler exposure checks ──

export async function checkCorsMisconfig(url, { timeoutMs = 8000 } = {}) {
  const probeOrigin = 'https://security-audit-cors-probe.invalid';
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, { headers: { origin: probeOrigin, 'user-agent': 'Universal-Security-Audit' }, signal: controller.signal });
    clearTimeout(t);
    const allowOrigin = res.headers.get('access-control-allow-origin');
    const allowCreds = res.headers.get('access-control-allow-credentials');
    const reflectsArbitraryOrigin = allowOrigin === probeOrigin || allowOrigin === '*';
    const misconfigured = reflectsArbitraryOrigin && String(allowCreds).toLowerCase() === 'true';
    return {
      checked: true,
      allowOrigin,
      allowCreds,
      reflectsArbitraryOrigin,
      misconfigured,
      note: misconfigured
        ? 'Reflects arbitrary Origin AND allows credentials — any site can make authenticated cross-origin requests on behalf of visiting users.'
        : reflectsArbitraryOrigin
          ? 'Reflects/wildcards Origin but does not allow credentials (lower risk).'
          : 'No permissive CORS reflection detected.',
    };
  } catch (e) {
    return { checked: false, error: String(e?.message || e) };
  }
}

export function findMixedContent(html = '', pageUrl = '') {
  if (!/^https:/i.test(pageUrl)) return { applicable: false, refs: [] };
  const refs = new Set();
  for (const m of html.matchAll(/(?:src|href)=["']http:\/\/([^"']+)["']/gi)) refs.add('http://' + m[1]);
  return { applicable: true, refs: [...refs] };
}

// `sitemapInfo` (optional) is the result already computed by Phase 1's URL discovery
// ({ sitemapUrl, robotsDeclaredSitemaps, sitemapDeclaredInRobots }) — passed in so this function
// doesn't redundantly re-guess sitemap paths and risk reporting a different answer than what the
// rest of the run actually used.
export async function summarizeCrawlerExposure(origin, sitemapInfo = null) {
  const fetchText = async (p) => {
    try {
      const res = await fetch(new URL(p, origin).toString(), { headers: { 'user-agent': 'Universal-Security-Audit' } });
      return res.ok ? await res.text() : null;
    } catch { return null; }
  };
  const robots = await fetchText('/robots.txt');
  const llms = await fetchText('/llms.txt');

  const disallowedPaths = robots
    ? [...robots.matchAll(/^disallow:\s*(.+)$/gim)].map((m) => m[1].trim()).filter((p) => p && p !== '/')
    : [];
  const sensitiveLookingDisallows = disallowedPaths.filter((p) => /admin|login|wp-|config|backup|private|internal|staging|test|debug/i.test(p));
  const robotsDeclaredSitemaps = robots ? [...robots.matchAll(/^sitemap:\s*(\S+)$/gim)].map((m) => m[1].trim()) : [];

  const hasSitemap = sitemapInfo ? !!sitemapInfo.sitemapUrl : null;
  const sitemapDeclaredInRobots = sitemapInfo ? !!sitemapInfo.sitemapDeclaredInRobots : robotsDeclaredSitemaps.length > 0;
  const sitemapUndeclaredButReachable = hasSitemap && robotsDeclaredSitemaps.length > 0 && !sitemapDeclaredInRobots;
  const sitemapDeclaredButUnreachable = robotsDeclaredSitemaps.length > 0 && !hasSitemap;

  return {
    hasRobots: !!robots,
    hasLlmsTxt: !!llms,
    hasSitemap,
    sitemapUrl: sitemapInfo?.sitemapUrl || null,
    robotsDeclaredSitemaps,
    sitemapDeclaredInRobots,
    sitemapUndeclaredButReachable,
    sitemapDeclaredButUnreachable,
    disallowedPathCount: disallowedPaths.length,
    sensitiveLookingDisallows,
    note: sensitiveLookingDisallows.length
      ? `robots.txt Disallow rules name ${sensitiveLookingDisallows.length} sensitive-looking path(s) — this is public and tells both search engines AND attackers/AI scrapers where to look, even though it doesn't block direct requests.`
      : 'No obviously sensitive path names found in robots.txt Disallow rules.',
  };
}
