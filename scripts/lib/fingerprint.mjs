// ── CMS/platform + hosting/CDN fingerprinting, DNS records, TLS cert info ──
import dns from 'node:dns/promises';
import tls from 'node:tls';

export function detectPlatform({ html = '', headers = {}, scriptSrcs = [], cookieNames = [] }) {
  const h = html.toLowerCase();
  const get = (name) => (headers.get ? headers.get(name) : headers[name]) || '';
  const server = String(get('server') || '').toLowerCase();
  const poweredBy = String(get('x-powered-by') || '').toLowerCase();
  const scripts = scriptSrcs.join(' ').toLowerCase();
  const cookies = cookieNames.join(' ').toLowerCase();

  const signals = [];
  const add = (platform, confidence, reason) => signals.push({ platform, confidence, reason });

  if (h.includes('wp-content') || h.includes('wp-includes') || scripts.includes('wp-content') || h.includes('name="generator" content="wordpress')) {
    add('WordPress', 'high', 'wp-content/wp-includes paths or generator meta tag found.');
  }
  if (h.includes('/sites/default/files') || h.includes('drupal.settings') || cookies.includes('has_js') || h.includes('drupal-')) {
    add('Drupal', 'high', 'Drupal-specific paths, settings object, or cookie found.');
  }
  if (h.includes('/media/jui/') || h.includes('joomla') || cookies.includes('joomla')) {
    add('Joomla', 'medium', 'Joomla-specific paths or cookie found.');
  }
  if (h.includes('cdn.shopify.com') || scripts.includes('cdn.shopify.com') || cookies.includes('_shopify')) {
    add('Shopify', 'high', 'Shopify CDN asset references or cookie found.');
  }
  if (h.includes('static.wixstatic.com') || scripts.includes('wixstatic') || h.includes('wix.com')) {
    add('Wix', 'high', 'Wix static asset host referenced.');
  }
  if (h.includes('assets.squarespace.com') || scripts.includes('squarespace')) {
    add('Squarespace', 'high', 'Squarespace asset host referenced.');
  }
  if (h.includes('webflow.js') || h.includes('assets.website-files.com') || h.includes('data-wf-page')) {
    add('Webflow', 'high', 'Webflow runtime script or data-wf-page attribute found.');
  }
  if (h.includes('/skin/frontend/') || h.includes('mage/cookies') || cookies.includes('frontend')) {
    add('Magento', 'medium', 'Magento-specific asset paths or cookie found.');
  }
  if (server.includes('cloudflare') && !signals.length) {
    // Cloudflare is hosting/CDN, not a CMS signal — handled separately.
  }
  if (h.includes('__next') || h.includes('/_next/static/')) add('Next.js (React)', 'high', '_next/static asset paths found.');
  if (h.includes('data-reactroot') || h.includes('__nuxt')) add('Nuxt/React SPA', 'medium', 'SPA framework hydration markers found.');

  signals.sort((a, b) => (b.confidence === 'high') - (a.confidence === 'high'));
  return signals.length ? signals : [{ platform: 'Unknown/Custom', confidence: 'low', reason: 'No known CMS/platform signature matched.' }];
}

export function detectHosting(headers = {}) {
  const get = (name) => String((headers.get ? headers.get(name) : headers[name]) || '');
  const server = get('server').toLowerCase();
  const signals = [];
  if (get('cf-ray') || server.includes('cloudflare')) signals.push({ provider: 'Cloudflare', via: 'cf-ray header / Server banner' });
  if (get('x-vercel-id')) signals.push({ provider: 'Vercel', via: 'x-vercel-id header' });
  if (get('x-nf-request-id') || get('x-nf-render-mode')) signals.push({ provider: 'Netlify', via: 'x-nf-* header' });
  if (get('x-served-by')?.toLowerCase().includes('fastly') || get('via')?.toLowerCase().includes('fastly')) signals.push({ provider: 'Fastly', via: 'x-served-by/via header' });
  if (server.includes('amazons3')) signals.push({ provider: 'AWS S3', via: 'Server banner' });
  if (get('x-amz-cf-id')) signals.push({ provider: 'AWS CloudFront', via: 'x-amz-cf-id header' });
  if (server.includes('apache')) signals.push({ provider: 'Apache (origin server)', via: 'Server banner' });
  if (server.includes('nginx')) signals.push({ provider: 'nginx (origin server)', via: 'Server banner' });
  if (get('x-github-request-id')) signals.push({ provider: 'GitHub Pages', via: 'x-github-request-id header' });
  if (get('x-pantheon-styx-hostname')) signals.push({ provider: 'Pantheon', via: 'x-pantheon header' });
  if (get('x-wpe-token') || server.includes('wpengine')) signals.push({ provider: 'WP Engine', via: 'header/Server banner' });
  return signals;
}

export async function lookupDnsRecords(hostname) {
  const out = { a: [], aaaa: [], mx: [], ns: [], txt: [], error: null };
  try { out.a = await dns.resolve4(hostname); } catch {}
  try { out.aaaa = await dns.resolve6(hostname); } catch {}
  try { out.mx = (await dns.resolveMx(hostname)).map((m) => `${m.exchange} (pri ${m.priority})`); } catch {}
  try { out.ns = await dns.resolveNs(hostname); } catch {}
  try { out.txt = (await dns.resolveTxt(hostname)).map((t) => t.join('')); } catch {}
  return out;
}

export function getTlsCertInfo(hostname, port = 443, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname, timeout: timeoutMs, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate?.();
      const protocol = socket.getProtocol?.();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;
      socket.end();
      if (!cert || !Object.keys(cert).length) {
        resolve({ ok: false, error: 'No certificate returned' });
        return;
      }
      const now = new Date();
      const validTo = new Date(cert.valid_to);
      const daysRemaining = Math.round((validTo - now) / (1000 * 60 * 60 * 24));
      resolve({
        ok: true,
        protocol,
        authorized,
        authError: authorized ? null : String(authError || ''),
        issuer: cert.issuer?.O || cert.issuer?.CN || 'unknown',
        subject: cert.subject?.CN || hostname,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysRemaining,
        isExpired: daysRemaining < 0,
        isExpiringSoon: daysRemaining >= 0 && daysRemaining < 21,
      });
    });
    socket.on('error', (e) => resolve({ ok: false, error: String(e?.message || e) }));
    socket.setTimeout(timeoutMs, () => { socket.destroy(); resolve({ ok: false, error: 'timeout' }); });
  });
}

const WEAK_TLS_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']);
export function isWeakTlsProtocol(protocol) {
  return WEAK_TLS_PROTOCOLS.has(protocol);
}
