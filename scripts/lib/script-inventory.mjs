// ── Third-party script/library inventory + CMS core & plugin version detection ──

// Recognize common CDN/library filename conventions, e.g. "jquery-3.6.0.min.js", "bootstrap.min.js?ver=4.6.0"
const VERSION_IN_FILENAME_RE = /([a-z][a-z0-9.\-]*?)[-.]v?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i;
const KNOWN_LIB_HOST_HINTS = [
  { re: /jquery(?!-ui)/i, name: 'jquery' },
  { re: /jquery-ui/i, name: 'jquery-ui' },
  { re: /bootstrap/i, name: 'bootstrap' },
  { re: /lodash/i, name: 'lodash' },
  { re: /underscore/i, name: 'underscore' },
  { re: /angular(?!js)/i, name: 'angular' },
  { re: /angular(?:js)?[.\-]/i, name: 'angularjs' },
  { re: /react-dom/i, name: 'react-dom' },
  { re: /react(?!-dom)/i, name: 'react' },
  { re: /vue(?:\.runtime)?[.\-]/i, name: 'vue' },
  { re: /moment/i, name: 'moment' },
  { re: /handlebars/i, name: 'handlebars' },
  { re: /swiper/i, name: 'swiper' },
  { re: /slick/i, name: 'slick' },
  { re: /fancybox/i, name: 'fancybox' },
  { re: /font-awesome|fontawesome/i, name: 'font-awesome' },
  { re: /gsap|tweenmax|tweenlite/i, name: 'gsap' },
  { re: /d3(?:\.v\d+)?[.\-]/i, name: 'd3' },
  { re: /chart(?:\.min)?\.js/i, name: 'chart.js' },
  { re: /select2/i, name: 'select2' },
  { re: /axios/i, name: 'axios' },
];

export function extractInventoryFromHtml(html = '', baseUrl) {
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]);
  const styles = [...html.matchAll(/<link[^>]+href=["']([^"']+)["'][^>]*rel=["']stylesheet["']/gi)].map((m) => m[1]);
  const generator = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(html)?.[1] || '';
  const absolutize = (u) => { try { return new URL(u, baseUrl).toString(); } catch { return u; } };
  return {
    scriptUrls: scripts.map(absolutize),
    styleUrls: styles.map(absolutize),
    generator,
  };
}

function versionFromPathSegment(url) {
  // Catches CDN conventions like cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.0/js/bootstrap.min.js
  // where the version is its own path segment rather than embedded in the filename or query string.
  try {
    const segments = new URL(url).pathname.split('/').filter(Boolean);
    const semverSegment = segments.find((s) => /^\d+\.\d+(?:\.\d+)?$/.test(s));
    return semverSegment || null;
  } catch { return null; }
}

export function identifyLibraries(urls = []) {
  const found = new Map();
  for (const url of urls) {
    let filename;
    try { filename = new URL(url).pathname.split('/').pop() || ''; } catch { filename = url; }
    const verMatch = VERSION_IN_FILENAME_RE.exec(filename);
    const queryVer = /[?&](?:ver|version|v)=([\d.]+)/i.exec(url)?.[1];
    for (const hint of KNOWN_LIB_HOST_HINTS) {
      if (hint.re.test(filename) || hint.re.test(url)) {
        const version = verMatch?.[2] || queryVer || versionFromPathSegment(url) || null;
        const key = hint.name;
        if (!found.has(key) || (version && !found.get(key).version)) {
          found.set(key, { name: hint.name, version, sourceUrl: url });
        }
        break;
      }
    }
  }
  return [...found.values()];
}

export function extractWpPluginsAndThemes(urls = []) {
  const plugins = new Map();
  const themes = new Map();
  for (const url of urls) {
    const pluginMatch = /\/wp-content\/plugins\/([^/]+)\//i.exec(url);
    const themeMatch = /\/wp-content\/themes\/([^/]+)\//i.exec(url);
    const queryVer = /[?&](?:ver|version)=([\d.]+)/i.exec(url)?.[1] || null;
    if (pluginMatch) {
      const slug = pluginMatch[1];
      if (!plugins.has(slug) || (queryVer && !plugins.get(slug).version)) plugins.set(slug, { slug, version: queryVer, sourceUrl: url });
    }
    if (themeMatch) {
      const slug = themeMatch[1];
      if (!themes.has(slug) || (queryVer && !themes.get(slug).version)) themes.set(slug, { slug, version: queryVer, sourceUrl: url });
    }
  }
  return { plugins: [...plugins.values()], themes: [...themes.values()] };
}

async function safeFetchText(url, timeoutMs = 6000) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, { signal: controller.signal, headers: { 'user-agent': 'Universal-Security-Audit' } });
    clearTimeout(t);
    if (!res.ok) return null;
    return await res.text();
  } catch { return null; }
}

export async function detectWpCoreVersion(origin, html, generator) {
  const genMatch = /WordPress\s+([\d.]+)/i.exec(generator || '');
  if (genMatch) return { version: genMatch[1], source: 'generator meta tag' };
  const emojiMatch = /wp-emoji-release\.min\.js\?ver=([\d.]+)/i.exec(html || '');
  if (emojiMatch) return { version: emojiMatch[1], source: 'wp-emoji script query param' };
  const readme = await safeFetchText(new URL('/readme.html', origin).toString());
  if (readme) {
    const m = /<br\s*\/?>\s*Version\s+([\d.]+)/i.exec(readme) || /Version\s+([\d.]+)/i.exec(readme);
    if (m) return { version: m[1], source: '/readme.html' };
  }
  return { version: null, source: null };
}

export async function fetchWpPluginReadmeVersion(origin, slug) {
  const readme = await safeFetchText(new URL(`/wp-content/plugins/${slug}/readme.txt`, origin).toString());
  if (!readme) return null;
  const m = /Stable tag:\s*([\d.]+)/i.exec(readme);
  return m ? m[1] : null;
}

export async function detectDrupalCoreVersion(origin, html, generator) {
  const genMatch = /Drupal\s+([\d.]+)/i.exec(generator || '');
  if (genMatch) return { version: genMatch[1], source: 'generator meta tag' };
  const changelog = await safeFetchText(new URL('/CHANGELOG.txt', origin).toString());
  if (changelog) {
    const m = /^Drupal\s+([\d.]+),/im.exec(changelog);
    if (m) return { version: m[1], source: '/CHANGELOG.txt' };
  }
  return { version: null, source: null };
}
