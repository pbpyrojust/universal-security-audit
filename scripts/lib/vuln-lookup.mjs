// ── Live vulnerability data sources: OSV.dev (npm-ecosystem JS libs) + WPScan (WordPress core/plugins/themes) ──

const osvCache = new Map();
const wpscanCache = new Map();

// Map detected front-end library names to their npm package name for OSV lookups.
const NPM_ECOSYSTEM_NAMES = {
  jquery: 'jquery',
  'jquery-ui': 'jquery-ui',
  bootstrap: 'bootstrap',
  lodash: 'lodash',
  underscore: 'underscore',
  angular: '@angular/core',
  angularjs: 'angular',
  react: 'react',
  'react-dom': 'react-dom',
  vue: 'vue',
  moment: 'moment',
  handlebars: 'handlebars',
  swiper: 'swiper',
  slick: 'slick-carousel',
  fancybox: '@fancyapps/fancybox',
  'font-awesome': 'font-awesome',
  gsap: 'gsap',
  d3: 'd3',
  chartjs: 'chart.js',
  'chart.js': 'chart.js',
  select2: 'select2',
  axios: 'axios',
};

export function npmPackageNameFor(libName) {
  return NPM_ECOSYSTEM_NAMES[String(libName || '').toLowerCase()] || null;
}

export async function osvLookup(packageName, version) {
  if (!packageName || !version) return { checked: false, vulns: [] };
  const key = `${packageName}@${version}`;
  if (osvCache.has(key)) return osvCache.get(key);
  const result = { checked: true, vulns: [], error: null };
  try {
    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ version, package: { name: packageName, ecosystem: 'npm' } }),
    });
    if (res.ok) {
      const data = await res.json();
      result.vulns = (data.vulns || []).map((v) => ({
        id: v.id,
        summary: v.summary || v.details?.slice(0, 200) || '',
        severity: (v.severity || []).map((s) => s.score).join(', ') || (v.database_specific?.severity || ''),
        url: v.references?.find((r) => r.type === 'ADVISORY' || r.type === 'WEB')?.url || `https://osv.dev/vulnerability/${v.id}`,
      }));
    } else {
      result.error = `HTTP ${res.status}`;
    }
  } catch (e) {
    result.error = String(e?.message || e);
  }
  osvCache.set(key, result);
  return result;
}

function wpscanHeaders(apiKey) {
  return apiKey ? { Authorization: `Token token=${apiKey}` } : {};
}

async function wpscanGet(pathSegment, apiKey) {
  const key = pathSegment;
  if (wpscanCache.has(key)) return wpscanCache.get(key);
  const result = { checked: true, vulns: [], error: null, rateLimited: false };
  try {
    const res = await fetch(`https://wpscan.com/api/v3/${pathSegment}`, { headers: wpscanHeaders(apiKey) });
    if (res.status === 429) {
      result.error = 'rate_limited';
      result.rateLimited = true;
    } else if (res.status === 401 || res.status === 403) {
      result.error = 'unauthorized (check WPSCAN_API_KEY)';
    } else if (res.status === 404) {
      // Not found = no known record for this slug/version; not an error.
    } else if (res.ok) {
      const data = await res.json();
      for (const entry of Object.values(data)) {
        for (const v of entry.vulnerabilities || []) {
          result.vulns.push({
            id: v.id,
            title: v.title,
            fixedIn: v.fixed_in || null,
            references: v.references?.url || v.references || [],
          });
        }
      }
    } else {
      result.error = `HTTP ${res.status}`;
    }
  } catch (e) {
    result.error = String(e?.message || e);
  }
  wpscanCache.set(key, result);
  return result;
}

export async function wpscanCoreLookup(version, apiKey) {
  if (!version) return { checked: false, vulns: [] };
  const normalized = version.replace(/\./g, '');
  return wpscanGet(`wordpresses/${normalized}`, apiKey);
}

export async function wpscanPluginLookup(slug, apiKey) {
  if (!slug) return { checked: false, vulns: [] };
  return wpscanGet(`plugins/${encodeURIComponent(slug)}`, apiKey);
}

export async function wpscanThemeLookup(slug, apiKey) {
  if (!slug) return { checked: false, vulns: [] };
  return wpscanGet(`themes/${encodeURIComponent(slug)}`, apiKey);
}
