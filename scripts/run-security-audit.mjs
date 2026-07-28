#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { chromium } from 'playwright';

import { gradeSecurityHeaders, gradeCookies } from './lib/security-headers.mjs';
import { detectPlatform, detectHosting, lookupDnsRecords, getTlsCertInfo, isWeakTlsProtocol } from './lib/fingerprint.mjs';
import { ADMIN_LOGIN_PATHS, EXPOSED_FILE_PATHS, EXPOSED_API_PATHS, probeAllPaths } from './lib/exposed-paths.mjs';
import {
  extractInventoryFromHtml, identifyLibraries, extractWpPluginsAndThemes,
  detectWpCoreVersion, fetchWpPluginReadmeVersion, detectDrupalCoreVersion,
} from './lib/script-inventory.mjs';
import { npmPackageNameFor, osvLookup, wpscanCoreLookup, wpscanPluginLookup, wpscanThemeLookup } from './lib/vuln-lookup.mjs';
import { scanForPii, detectPaymentProcessors } from './lib/pii-payment.mjs';
import { checkCorsMisconfig, findMixedContent, summarizeCrawlerExposure } from './lib/misc-checks.mjs';
import { computeRiskGrade, sortFindingsBySeverity, isGradeBelow, hasFindingAtOrAbove } from './lib/scoring.mjs';
import {
  checkSubdomainTakeover, checkHttpMethods, checkOpenRedirect, checkMissingSri,
  checkExposedSourceMaps, checkEmailAuthRecords, enumerateWpAuthors,
  checkInsecureLoginForms, checkVerboseErrors, scanCookiesForJwt,
} from './lib/pentest-recon.mjs';
import { loadBranding, buildSecurityDashboardHtml } from './lib/report-builder.mjs';
import { loadWordlistEntries } from './lib/exposed-paths.mjs';
import { resolveIntensity } from './lib/intensity.mjs';
import { scanPorts, SENSITIVE_PORTS } from './lib/port-scan.mjs';
import { enumerateSubdomainsCrtSh, checkLiveness } from './lib/subdomain-enum.mjs';
import { rdapLookup } from './lib/whois-lookup.mjs';
import { configureFetchProxy, playwrightProxyOption } from './lib/proxy-support.mjs';
import {
  isLoggedIntoWpAdmin, scanWpPlugins, scanWpThemes, scanWpCoreAndPhp, scanWpUsers,
  detectSecurityPlugins, checkPhpEol,
} from './lib/wp-admin-audit.mjs';

// ── CLI / generic helpers ───────────────────────────────────────────────
function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.replace(/^--/, '');
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) args[key] = true;
    else { args[key] = next; i++; }
  }
  return args;
}
function slugifySite(site) { try { return new URL(site).hostname.replace(/^www\./, ''); } catch { return 'site'; } }
function runId(site) {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${slugifySite(site)}-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}
function normalizeUrl(u) {
  try {
    const url = new URL(u);
    url.hash = '';
    if (url.pathname !== '/' && url.pathname.endsWith('/')) url.pathname = url.pathname.slice(0, -1);
    return url.toString();
  } catch { return String(u || '').trim(); }
}
function sameOrigin(a, b) { try { return new URL(a).origin === new URL(b).origin; } catch { return false; } }
function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }
function escapeCsv(value) {
  const s = String(value ?? '');
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}
function writeCsv(filePath, columns, rows) {
  const lines = [columns.join(',')];
  for (const row of rows) lines.push(columns.map((col) => escapeCsv(row[col])).join(','));
  fs.writeFileSync(filePath, lines.join('\n') + '\n', 'utf8');
}
function semverParts(v) { return String(v || '0').split('.').map((n) => parseInt(n, 10) || 0); }
function semverLt(a, b) {
  const pa = semverParts(a), pb = semverParts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return false;
}

async function fetchWithHeaders(url, { timeoutMs = 15000 } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { redirect: 'follow', headers: { 'user-agent': 'Universal-Security-Audit' }, signal: controller.signal });
    clearTimeout(t);
    const setCookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
    return { ok: true, status: res.status, headers: res.headers, setCookies, finalUrl: res.url };
  } catch (e) {
    clearTimeout(t);
    return { ok: false, error: String(e?.message || e) };
  }
}

async function buildRobotsMatcher(startUrl) {
  try {
    const robotsUrl = new URL('/robots.txt', startUrl).toString();
    const res = await fetch(robotsUrl, { headers: { 'user-agent': 'Universal-Security-Audit' } });
    if (!res.ok) throw new Error('no robots.txt');
    const text = await res.text();
    const disallows = [];
    for (const line of text.split(/\r?\n/g)) {
      const m = /^disallow:\s*(.+)$/i.exec(line.trim());
      if (m) disallows.push(m[1].trim());
    }
    function isAllowedUrl(url) {
      try {
        const u = new URL(url);
        const p = `${u.pathname}${u.search || ''}`;
        for (const rule of disallows) {
          if (!rule || rule === '/') continue;
          const norm = rule.replace(/\*$/, '');
          if (p.startsWith(norm) || p.includes(norm.replace(/\*/g, ''))) return false;
        }
        return true;
      } catch { return true; }
    }
    return { isAllowedUrl };
  } catch { return { isAllowedUrl: null }; }
}

// ── Authenticated-scan support (HTTP basic + form login) ────────────────
function loadAuthConfig(filePath) {
  try { return JSON.parse(fs.readFileSync(path.resolve(process.cwd(), filePath), 'utf8')); }
  catch (e) { throw new Error(`Could not read auth config at ${filePath}: ${String(e?.message || e)}`); }
}
function getAuthSettings(args) {
  let cfg = {};
  if (args['auth-config']) cfg = loadAuthConfig(args['auth-config']);
  const httpUsername = args['http-username'] || process.env.USA_HTTP_USERNAME || cfg.httpUsername || '';
  const httpPassword = args['http-password'] || process.env.USA_HTTP_PASSWORD || cfg.httpPassword || '';
  const loginUrl = args['login-url'] || cfg.loginUrl || '';
  const username = args['username'] || process.env.USA_LOGIN_USERNAME || cfg.username || '';
  const password = args['password'] || process.env.USA_LOGIN_PASSWORD || cfg.password || '';
  const usernameSelector = args['username-selector'] || cfg.usernameSelector || "input[name='log'], input[name='username'], input[type='email']";
  const passwordSelector = args['password-selector'] || cfg.passwordSelector || "input[name='pwd'], input[name='password'], input[type='password']";
  const submitSelector = args['submit-selector'] || cfg.submitSelector || "button[type='submit'], input[type='submit']";
  const readySelector = args['ready-selector'] || cfg.readySelector || '';
  const postLoginWaitMs = Number(args['post-login-wait-ms'] || cfg.postLoginWaitMs || 2000);
  return {
    httpCredentials: httpUsername || httpPassword ? { username: httpUsername, password: httpPassword } : null,
    formAuth: loginUrl && username ? { loginUrl, username, password, usernameSelector, passwordSelector, submitSelector, readySelector, postLoginWaitMs } : null,
  };
}
async function maybePerformFormLogin(page, formAuth, slowMode = false) {
  if (!formAuth) return false;
  statusMsg('🔐', c.cyan, `Attempting form login at ${formAuth.loginUrl}`);
  try {
    await page.goto(formAuth.loginUrl, { waitUntil: slowMode ? 'domcontentloaded' : 'networkidle', timeout: 45000 });
    await page.locator(formAuth.usernameSelector).first().fill(formAuth.username);
    await page.locator(formAuth.passwordSelector).first().fill(formAuth.password || '');
    if (formAuth.submitSelector) {
      await Promise.allSettled([
        page.waitForLoadState(slowMode ? 'domcontentloaded' : 'networkidle', { timeout: 20000 }),
        page.locator(formAuth.submitSelector).first().click(),
      ]);
    } else {
      await page.keyboard.press('Enter');
      await page.waitForLoadState(slowMode ? 'domcontentloaded' : 'networkidle', { timeout: 20000 }).catch(() => {});
    }
    if (formAuth.readySelector) await page.locator(formAuth.readySelector).first().waitFor({ state: 'visible', timeout: 20000 });
    else await page.waitForTimeout(formAuth.postLoginWaitMs || 2000);
    statusMsg('🔐', c.brightGreen, 'Form login step completed.');
    return true;
  } catch (e) {
    statusMsg('⚠', c.brightYellow, `Form login failed: ${String(e?.message || e)}`);
    return false;
  }
}

// ── Terminal UI helpers (shared style with universal-seo-audit / universal-accessibility-audit) ──
const c = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  brightRed: '\x1b[91m', brightGreen: '\x1b[92m', brightYellow: '\x1b[93m',
  brightCyan: '\x1b[96m', brightMagenta: '\x1b[95m', brightBlue: '\x1b[94m',
};
const rainbowColors = [c.brightRed, c.brightYellow, c.brightGreen, c.brightCyan, c.brightBlue, c.brightMagenta];
function rainbow(text) { return [...text].map((ch, i) => ch === ' ' ? ch : `${rainbowColors[i % rainbowColors.length]}${ch}`).join('') + c.reset; }
function formatDuration(ms) {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60), rem = s % 60;
  return rem > 0 ? `${m}m ${rem}s` : `${m}m`;
}
// When --json is set, stdout is reserved for the final JSON document (so it can be piped to jq/etc);
// all progress/decorative output moves to stderr instead of being suppressed outright.
function out(line) { (jsonOut ? console.error : console.log)(line); }
function phaseHeader(label, icon = '▸') {
  out('');
  out(`  ${rainbow(icon)} ${c.bold}${c.brightCyan}${label}${c.reset} ${c.dim}${'─'.repeat(Math.max(0, 52 - label.length))}${c.reset}`);
}
function phaseDone(label, elapsed) { out(`    ${c.brightGreen}✔${c.reset} ${label} ${c.dim}in${c.reset} ${c.brightYellow}${formatDuration(elapsed)}${c.reset}`); }
function statusMsg(icon, color, msg) { out(`    ${color}${icon}${c.reset} ${msg}`); }
function sevColor(sev) {
  const map = { critical: c.brightRed, high: c.red, medium: c.brightYellow, low: c.yellow, info: c.dim };
  return `${map[sev] || c.dim}${sev.toUpperCase()}${c.reset}`;
}

// ── Findings collection ─────────────────────────────────────────────────
const findings = [];
function addFinding({ category, severity, title, detail, url = '', evidence = '' }) {
  findings.push({ category, severity, title, detail, url, evidence });
}

// ── Main ─────────────────────────────────────────────────────────────────
const args = parseArgs(process.argv);
if (!args.site) { console.error('Missing --site'); process.exit(1); }
const site = normalizeUrl(args.site);
const origin = new URL(site).origin;
const hostname = new URL(site).hostname;
const maxPages = args['max-pages'] ? Number(args['max-pages']) : 10;
const slowMode = Boolean(args['slow']);
const respectRobots = Boolean(args['respect-robots']);
const skipExposedPaths = Boolean(args['skip-exposed-paths']);
const skipCve = Boolean(args['skip-cve']);
const skipRecon = Boolean(args['skip-recon']);
const skipPortScan = Boolean(args['skip-port-scan']);
const skipSubdomainEnum = Boolean(args['skip-subdomain-enum']);
const skipWhois = Boolean(args['skip-whois']);
const skipAdminAudit = Boolean(args['skip-admin-audit']);
const wpscanApiKey = args['wpscan-key'] || process.env.WPSCAN_API_KEY || '';
const branding = loadBranding(fs, path, args['brand-config']);
const intensity = resolveIntensity(args['intensity']);
const proxyUrl = args['proxy'] || '';
if (proxyUrl) configureFetchProxy(proxyUrl);
const failOn = args['fail-on'] ? String(args['fail-on']).toLowerCase() : '';
const minGrade = args['min-grade'] ? String(args['min-grade']).toUpperCase() : '';
const jsonOut = Boolean(args['json']);
const authSettings = getAuthSettings(args);
const outDir = path.resolve('reports/' + runId(site));
fs.mkdirSync(outDir, { recursive: true });

const auditStart = Date.now();
out('');
out(`  ${rainbow('╔══════════════════════════════════════════════════════════╗')}`);
out(`  ${rainbow('║')}  ${c.bold}${c.brightRed}🛡  Universal Security Audit${c.reset}                          ${rainbow('║')}`);
out(`  ${rainbow('║')}  ${c.dim}Attack Surface · Headers · CVEs · PII · Payments${c.reset}       ${rainbow('║')}`);
out(`  ${rainbow('╚══════════════════════════════════════════════════════════╝')}`);
out('');
out(`  ${c.brightMagenta}🎯${c.reset} ${c.bold}Target:${c.reset}     ${c.brightCyan}${site}${c.reset}`);
out(`  ${c.brightMagenta}📁${c.reset} ${c.bold}Output:${c.reset}     ${c.dim}${outDir}${c.reset}`);
out(`  ${c.brightMagenta}🔑${c.reset} ${c.bold}WPScan key:${c.reset} ${wpscanApiKey ? `${c.brightGreen}configured${c.reset}` : `${c.dim}not set (WordPress CVE lookups will be skipped)${c.reset}`}`);
out(`  ${c.brightMagenta}⚡${c.reset} ${c.bold}Intensity:${c.reset}  ${args['intensity'] || 'normal'}${proxyUrl ? `  ${c.dim}·${c.reset} proxying via ${proxyUrl}` : ''}`);
if (authSettings.httpCredentials || authSettings.formAuth) console.log(`  ${c.brightMagenta}🔐${c.reset} ${c.bold}Auth:${c.reset}       ${authSettings.formAuth ? 'form login configured' : 'HTTP basic credentials configured'}`);
statusMsg('⚠', c.brightYellow, 'Authorized-use only — this tool actively probes admin/config paths and login forms. Only run it against sites you own or have written permission to test.');

let robotsCfg = { isAllowedUrl: null };
if (respectRobots) robotsCfg = await buildRobotsMatcher(site);

// ── Phase 1: Setup / URL discovery ──────────────────────────────────────
const NON_PAGE_EXTENSION_RE = /\.(jpg|jpeg|png|gif|webp|avif|bmp|ico|svg|tiff?|heic|pdf|docx?|xlsx?|pptx?|zip|rar|7z|tar|gz|dmg|exe|mp3|mp4|m4a|mov|avi|wav|ogg|ogv|webm|flac|woff2?|ttf|eot|otf|csv|xml|json|rss|css|js|mjs)$/i;
function isCrawlablePage(u) { try { return !NON_PAGE_EXTENSION_RE.test(new URL(u).pathname); } catch { return true; } }
async function fetchXml(url) {
  const res = await fetch(url, { headers: { 'user-agent': 'Universal-Security-Audit' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}
function parseSitemapLocs(xml) { return [...xml.matchAll(/<loc>(.*?)<\/loc>/gsi)].map((m) => normalizeUrl(m[1].trim())).filter(Boolean); }
async function discoverUrlsFromSitemap(site) {
  const base = new URL(site).origin;
  const candidates = [`${base}/sitemap_index.xml`, `${base}/wp-sitemap.xml`, `${base}/sitemap.xml`];
  let xml = null, sitemapUrl = null;
  for (const cand of candidates) {
    try { xml = await fetchXml(cand); sitemapUrl = cand; break; } catch {}
  }
  if (!xml) throw new Error('Could not fetch sitemap');
  let urls = [];
  if (/<sitemapindex/i.test(xml)) {
    const childSitemaps = parseSitemapLocs(xml);
    for (const su of childSitemaps.slice(0, 20)) {
      try { urls.push(...parseSitemapLocs(await fetchXml(su))); } catch {}
    }
  } else {
    urls = parseSitemapLocs(xml);
  }
  return { sitemapUrl, urls: [...new Set(urls)].filter((u) => sameOrigin(u, site) && isCrawlablePage(u)) };
}
async function crawlForUrls(site, { maxPages, isAllowedUrl }) {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const seen = new Set([site]);
  const queue = [site];
  while (queue.length && seen.size < maxPages) {
    const url = queue.shift();
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      const hrefs = await page.$$eval('a[href]', (as) => as.map((a) => a.href));
      for (const href of hrefs) {
        const abs = normalizeUrl(href);
        if (!sameOrigin(abs, site) || !isCrawlablePage(abs) || seen.has(abs)) continue;
        if (isAllowedUrl && !isAllowedUrl(abs)) continue;
        if (seen.size >= maxPages) break;
        seen.add(abs);
        queue.push(abs);
      }
    } catch {}
  }
  await browser.close();
  return [...seen];
}

phaseHeader('Phase 1: URL discovery', '🗺️');
const discStart = Date.now();
let pageUrls = [site];
if (args['crawl']) {
  pageUrls = await crawlForUrls(site, { maxPages, isAllowedUrl: robotsCfg.isAllowedUrl });
  statusMsg('🕷️', c.brightGreen, `Crawled ${pageUrls.length} page(s) via link-following.`);
} else {
  try {
    const { sitemapUrl, urls } = await discoverUrlsFromSitemap(site);
    pageUrls = urls.length ? [...new Set([site, ...urls])].slice(0, maxPages) : [site];
    statusMsg('🌐', c.brightGreen, `Found ${urls.length} URL(s) from ${sitemapUrl}; scanning ${pageUrls.length} page(s).`);
  } catch {
    statusMsg('⚠', c.brightYellow, 'No sitemap found. Scanning homepage only — pass --crawl to discover more pages by following links.');
  }
}
if (robotsCfg.isAllowedUrl) pageUrls = pageUrls.filter((u) => robotsCfg.isAllowedUrl(u));
phaseDone('URL discovery', Date.now() - discStart);

// ── Phase 2: Browser setup ──────────────────────────────────────────────
phaseHeader('Phase 2: Browser setup', '🚀');
const setupStart = Date.now();
const browser = await chromium.launch({ headless: true, proxy: playwrightProxyOption(proxyUrl) });
const context = await browser.newContext({
  userAgent: 'Mozilla/5.0 (compatible; Universal-Security-Audit/1.0)',
  httpCredentials: authSettings.httpCredentials || undefined,
});
phaseDone('Browser ready', Date.now() - setupStart);

// ── Phase 3: Site-wide checks (headers, cookies, TLS, hosting, CORS, crawler exposure) ──
phaseHeader('Phase 3: Site-wide checks', '🔍');
const siteWideStart = Date.now();
const homepageFetch = await fetchWithHeaders(site);
let homepageHeaders = {};
if (homepageFetch.ok) {
  homepageHeaders = homepageFetch.headers;
  const grade = gradeSecurityHeaders(homepageHeaders, { isHttps: site.startsWith('https:') });
  statusMsg('📋', grade.score >= 75 ? c.brightGreen : grade.score >= 50 ? c.brightYellow : c.brightRed, `Security header grade: ${c.bold}${grade.grade}${c.reset} (${grade.score}/100)`);
  for (const check of grade.checks) {
    if (check.severity === 'ok') continue;
    addFinding({ category: 'headers', severity: check.severity, title: `${check.header}: ${check.status}`, detail: check.note, url: site });
  }
  const cookieIssues = gradeCookies(homepageFetch.setCookies);
  for (const ci of cookieIssues) {
    addFinding({ category: 'cookies', severity: 'medium', title: `Cookie "${ci.name}" missing flags`, detail: ci.issues.join(', '), url: site });
  }
} else {
  statusMsg('✖', c.brightRed, `Could not fetch homepage headers: ${homepageFetch.error}`);
}

const hostingSignals = detectHosting(homepageHeaders);
if (hostingSignals.length) statusMsg('☁️', c.brightCyan, `Hosting/CDN: ${hostingSignals.map((s) => s.provider).join(', ')}`);

let dnsRecords = { a: [], mx: [], ns: [], txt: [] };
try {
  dnsRecords = await lookupDnsRecords(hostname);
  statusMsg('🌐', c.dim, `DNS: ${dnsRecords.a.length} A record(s), ${dnsRecords.ns.length} NS, ${dnsRecords.mx.length} MX`);
} catch {}

let tlsInfo = { ok: false };
if (site.startsWith('https:')) {
  tlsInfo = await getTlsCertInfo(hostname);
  if (tlsInfo.ok) {
    statusMsg('🔒', tlsInfo.isExpired ? c.brightRed : tlsInfo.isExpiringSoon ? c.brightYellow : c.brightGreen, `TLS: ${tlsInfo.protocol}, cert expires in ${tlsInfo.daysRemaining}d (issuer: ${tlsInfo.issuer})`);
    if (tlsInfo.isExpired) addFinding({ category: 'tls', severity: 'critical', title: 'TLS certificate expired', detail: `Expired ${-tlsInfo.daysRemaining} day(s) ago.`, url: site });
    else if (tlsInfo.isExpiringSoon) addFinding({ category: 'tls', severity: 'medium', title: 'TLS certificate expiring soon', detail: `Expires in ${tlsInfo.daysRemaining} day(s).`, url: site });
    if (isWeakTlsProtocol(tlsInfo.protocol)) addFinding({ category: 'tls', severity: 'high', title: `Weak TLS protocol negotiated: ${tlsInfo.protocol}`, detail: 'Server should disable protocols older than TLS 1.2.', url: site });
    if (!tlsInfo.authorized) addFinding({ category: 'tls', severity: 'high', title: 'TLS certificate not trusted', detail: tlsInfo.authError || 'Certificate validation failed.', url: site });
  } else {
    statusMsg('⚠', c.brightYellow, `TLS check failed: ${tlsInfo.error}`);
  }
}

const corsResult = await checkCorsMisconfig(site);
if (corsResult.checked && corsResult.misconfigured) {
  addFinding({ category: 'cors', severity: 'high', title: 'Permissive CORS with credentials', detail: corsResult.note, url: site });
  statusMsg('⚠', c.brightRed, 'CORS misconfiguration detected (reflects arbitrary Origin + allows credentials).');
} else if (corsResult.checked && corsResult.reflectsArbitraryOrigin) {
  addFinding({ category: 'cors', severity: 'low', title: 'CORS reflects/wildcards Origin', detail: corsResult.note, url: site });
}

const crawlerExposure = await summarizeCrawlerExposure(origin);
statusMsg('🤖', c.dim, `robots.txt: ${crawlerExposure.hasRobots ? 'present' : 'absent'} · llms.txt: ${crawlerExposure.hasLlmsTxt ? 'present' : 'absent'} · sitemap: ${crawlerExposure.hasSitemap ? 'present' : 'absent'}`);
if (crawlerExposure.sensitiveLookingDisallows.length) {
  addFinding({ category: 'crawler-exposure', severity: 'info', title: 'robots.txt names sensitive-looking paths', detail: `${crawlerExposure.note} Paths: ${crawlerExposure.sensitiveLookingDisallows.join(', ')}`, url: new URL('/robots.txt', origin).toString() });
}
phaseDone('Site-wide checks', Date.now() - siteWideStart);

const apexDomain = hostname.split('.').slice(-2).join('.');

// ── Phase 4: WHOIS / domain registration ─────────────────────────────────
let whois = { checked: false };
if (!skipWhois) {
  phaseHeader('Phase 4: WHOIS / domain registration', '📇');
  const whoisStart = Date.now();
  whois = await rdapLookup(apexDomain);
  if (whois.checked) {
    statusMsg('📇', c.dim, `Registrar: ${whois.registrar || 'unknown'} · expires ${whois.expiration ? new Date(whois.expiration).toISOString().slice(0, 10) : 'unknown'}`);
    if (whois.isExpired) addFinding({ category: 'domain-registration', severity: 'critical', title: 'Domain registration has expired', detail: `Registrar: ${whois.registrar || 'unknown'}. Expired ${-whois.daysUntilExpiration} day(s) ago — the domain can be lost/hijacked.`, url: `whois:${apexDomain}` });
    else if (whois.isExpiringSoon) addFinding({ category: 'domain-registration', severity: 'high', title: 'Domain registration expiring soon', detail: `Registrar: ${whois.registrar || 'unknown'}. Expires in ${whois.daysUntilExpiration} day(s) — renew to avoid an expiration-based takeover.`, url: `whois:${apexDomain}` });
  } else {
    statusMsg('⚠', c.brightYellow, `WHOIS/RDAP lookup failed: ${whois.error}`);
  }
  phaseDone('WHOIS / domain registration', Date.now() - whoisStart);
} else {
  statusMsg('⏭', c.dim, 'Skipping WHOIS/RDAP lookup (--skip-whois).');
}

// ── Phase 5: Subdomain enumeration (passive, crt.sh) ─────────────────────
let discoveredSubdomains = [];
if (!skipSubdomainEnum) {
  phaseHeader('Phase 5: Subdomain enumeration', '🌐');
  const subStart = Date.now();
  const enumResult = await enumerateSubdomainsCrtSh(apexDomain);
  if (enumResult.checked) {
    discoveredSubdomains = enumResult.subdomains;
    statusMsg('🌐', c.brightGreen, `Found ${discoveredSubdomains.length} subdomain(s) via certificate-transparency logs.`);
    if (discoveredSubdomains.length) {
      const liveness = await checkLiveness(discoveredSubdomains, { limit: intensity.subdomainLivenessLimit });
      const alive = liveness.filter((l) => l.alive);
      statusMsg('🌐', c.dim, `${alive.length}/${liveness.length} checked subdomain(s) responded (out of ${discoveredSubdomains.length} discovered total).`);
      addFinding({ category: 'subdomain-enum', severity: 'info', title: `${discoveredSubdomains.length} subdomain(s) discovered via certificate-transparency logs`, detail: `Expands the known attack surface beyond the scanned host. Live examples: ${alive.slice(0, 8).map((a) => a.host).join(', ') || 'none checked'}`, url: `https://crt.sh/?q=%25.${apexDomain}` });
    }
  } else {
    statusMsg('⚠', c.brightYellow, `Subdomain enumeration failed: ${enumResult.error} (crt.sh is a free community service and is sometimes slow/unavailable — this isn't necessarily a problem with the target)`);
  }
  phaseDone('Subdomain enumeration', Date.now() - subStart);
} else {
  statusMsg('⏭', c.dim, 'Skipping subdomain enumeration (--skip-subdomain-enum).');
}

// ── Phase 6: Port scan (TCP connect scan, common service ports) ─────────
let portResults = [];
if (!skipPortScan) {
  phaseHeader('Phase 6: Port scan', '🔌');
  const portStart = Date.now();
  portResults = await scanPorts(hostname, intensity.portScan);
  const open = portResults.filter((r) => r.state === 'open');
  statusMsg('🔌', open.length ? c.brightYellow : c.brightGreen, `${open.length}/${portResults.length} scanned port(s) open.`);
  for (const p of open) {
    const sensitive = SENSITIVE_PORTS.has(p.port);
    addFinding({
      category: 'port-scan',
      severity: sensitive ? 'high' : 'info',
      title: `Port ${p.port} (${p.name}) is open`,
      detail: sensitive ? `${p.name} is not normally expected to be reachable from the public internet — verify this is intentional and firewalled to trusted IPs only.${p.banner ? ` Banner: "${p.banner}"` : ''}` : `${p.banner ? `Banner: "${p.banner}"` : 'No banner volunteered.'}`,
      url: `${hostname}:${p.port}`,
    });
  }
  phaseDone('Port scan', Date.now() - portStart);
} else {
  statusMsg('⏭', c.dim, 'Skipping port scan (--skip-port-scan).');
}

// ── Phase 7: Exposed path / admin / API discovery ────────────────────────
let pathResults = [];
if (!skipExposedPaths) {
  phaseHeader('Phase 7: Exposed path & admin/API discovery', '🔎');
  const pathStart = Date.now();
  let allPaths = [...ADMIN_LOGIN_PATHS, ...EXPOSED_FILE_PATHS, ...EXPOSED_API_PATHS];
  if (args['wordlist']) {
    try {
      const wordlistEntries = loadWordlistEntries(fs, path.resolve(process.cwd(), args['wordlist']));
      allPaths = [...allPaths, ...wordlistEntries];
      statusMsg('📜', c.dim, `Loaded ${wordlistEntries.length} additional path(s) from --wordlist.`);
    } catch (e) {
      statusMsg('⚠', c.brightYellow, `Could not read --wordlist: ${String(e?.message || e)}`);
    }
  }
  pathResults = await probeAllPaths(origin, allPaths, { isAllowedUrl: respectRobots ? robotsCfg.isAllowedUrl : null, delayMs: slowMode ? 400 : intensity.exposedPathDelayMs, concurrency: intensity.exposedPathConcurrency });
  const exposed = pathResults.filter((r) => r.exists);
  for (const r of exposed) {
    const isAdminLogin = ADMIN_LOGIN_PATHS.some((p) => p.path === r.path);
    const sev = isAdminLogin ? 'info' : (r.severity || 'medium');
    addFinding({
      category: isAdminLogin ? 'admin-login' : (EXPOSED_API_PATHS.some((p) => p.path === r.path) ? 'exposed-api' : 'exposed-path'),
      severity: r.directoryListing ? 'high' : sev,
      title: `${r.label} reachable (HTTP ${r.status})`,
      detail: r.directoryListing ? 'Directory listing is enabled — full file listing exposed.' : 'Publicly reachable at this path.',
      url: r.url,
    });
  }
  statusMsg('🔎', exposed.length ? c.brightYellow : c.brightGreen, `${exposed.length}/${pathResults.length} probed path(s) responded publicly.`);
  phaseDone('Exposed path discovery', Date.now() - pathStart);
} else {
  statusMsg('⏭', c.dim, 'Skipping exposed-path discovery (--skip-exposed-paths).');
}

// ── Phase 8: Page scanning (platform fingerprint, script inventory, PII, payments) ──
phaseHeader('Phase 8: Page scanning', '📄');
const scanStart = Date.now();
let allScriptUrls = [];
let allStyleUrls = [];
let siteGenerator = '';
let siteHtmlSample = '';
const pageResults = [];
for (let i = 0; i < pageUrls.length; i++) {
  const url = pageUrls[i];
  const page = await context.newPage();
  try {
    await page.goto(url, { waitUntil: slowMode ? 'domcontentloaded' : 'networkidle', timeout: 45000 });
    await page.waitForTimeout(slowMode ? 1500 : 500);
    const html = await page.content();
    const cookies = await context.cookies();
    const inv = extractInventoryFromHtml(html, url);
    allScriptUrls.push(...inv.scriptUrls);
    allStyleUrls.push(...inv.styleUrls);
    if (!siteGenerator && inv.generator) siteGenerator = inv.generator;
    if (i === 0) siteHtmlSample = html;

    const platformSignals = detectPlatform({ html, headers: homepageHeaders, scriptSrcs: inv.scriptUrls, cookieNames: cookies.map((ck) => ck.name) });
    const pii = scanForPii(html);
    const payments = detectPaymentProcessors(html, inv.scriptUrls);
    const mixed = findMixedContent(html, url);
    const missingSri = checkMissingSri(html, origin);
    const insecureLoginForms = checkInsecureLoginForms(html, url);
    const jwtIssues = scanCookiesForJwt(cookies);

    if (pii.secrets.length) {
      for (const s of pii.secrets) addFinding({ category: 'pii', severity: 'critical', title: `Exposed ${s.type} in page source`, detail: `${s.count} occurrence(s), e.g. "${s.sample}"`, url });
    }
    if (pii.ssnLike.length) addFinding({ category: 'pii', severity: 'high', title: 'SSN-like number(s) found in page content', detail: `${pii.ssnLike.length} match(es).`, url });
    if (pii.cardLike.length) addFinding({ category: 'pii', severity: 'critical', title: 'Credit-card-like number(s) found in page content', detail: `${pii.cardLike.length} Luhn-valid match(es): ${pii.cardLike.slice(0, 3).join(', ')}`, url });
    if (pii.emails.length) addFinding({ category: 'pii', severity: 'info', title: `${pii.emails.length} email address(es) exposed on page`, detail: pii.emails.slice(0, 5).join(', '), url });
    if (mixed.applicable && mixed.refs.length) addFinding({ category: 'mixed-content', severity: 'medium', title: `${mixed.refs.length} mixed-content (http://) resource(s) on HTTPS page`, detail: mixed.refs.slice(0, 5).join(', '), url });
    if (missingSri.length) addFinding({ category: 'sri', severity: 'low', title: `${missingSri.length} cross-origin script/style tag(s) missing Subresource Integrity`, detail: missingSri.slice(0, 5).join(', '), url });
    for (const f of insecureLoginForms) addFinding({ category: 'insecure-login-form', severity: 'critical', title: 'Login form submits credentials over plaintext HTTP', detail: `${f.reason} (action: ${f.action})`, url });
    for (const j of jwtIssues) addFinding({ category: 'jwt', severity: j.alg && String(j.alg).toLowerCase() === 'none' ? 'critical' : 'medium', title: `JWT cookie "${j.cookieName}" has weak claims`, detail: j.issues.join('; '), url });

    pageResults.push({ url, platformSignals, pii, payments, mixed });
    statusMsg('✔', c.brightGreen, `[${i + 1}/${pageUrls.length}] ${url}`);
  } catch (e) {
    statusMsg('✖', c.brightRed, `[${i + 1}/${pageUrls.length}] ${url} — ${String(e?.message || e)}`);
  } finally {
    await page.close();
  }
}
phaseDone('Page scanning', Date.now() - scanStart);

// ── Phase 9: Platform + third-party library inventory ──────────────────
phaseHeader('Phase 9: Platform & library inventory', '📦');
const invStart = Date.now();
const platformSignals = detectPlatform({ html: siteHtmlSample, headers: homepageHeaders, scriptSrcs: allScriptUrls, cookieNames: [] });
const primaryPlatform = platformSignals[0]?.platform || 'Unknown/Custom';
statusMsg('🧩', c.brightCyan, `Detected platform: ${c.bold}${primaryPlatform}${c.reset} (${platformSignals[0]?.confidence || 'low'} confidence)`);

const libraries = identifyLibraries([...allScriptUrls, ...allStyleUrls]);
statusMsg('📚', c.dim, `${libraries.length} known front-end librar${libraries.length === 1 ? 'y' : 'ies'} detected.`);

let wpCore = { version: null }, drupalCore = { version: null };
let wpPlugins = [], wpThemes = [];
if (primaryPlatform === 'WordPress') {
  wpCore = await detectWpCoreVersion(origin, siteHtmlSample, siteGenerator);
  const extracted = extractWpPluginsAndThemes([...allScriptUrls, ...allStyleUrls]);
  wpPlugins = extracted.plugins;
  wpThemes = extracted.themes;
  for (const p of wpPlugins) {
    if (!p.version) {
      const readmeVer = await fetchWpPluginReadmeVersion(origin, p.slug);
      if (readmeVer) p.version = readmeVer;
    }
  }
  statusMsg('🔧', c.dim, `WordPress core: ${wpCore.version || 'unknown'} · ${wpPlugins.length} plugin(s), ${wpThemes.length} theme(s) detected.`);
} else if (primaryPlatform === 'Drupal') {
  drupalCore = await detectDrupalCoreVersion(origin, siteHtmlSample, siteGenerator);
  statusMsg('🔧', c.dim, `Drupal core: ${drupalCore.version || 'unknown'}`);
}
phaseDone('Platform & library inventory', Date.now() - invStart);

// ── Phase 10: CVE / known-vulnerability lookups (OSV.dev + WPScan) ───────
const vulnResults = [];
if (!skipCve) {
  phaseHeader('Phase 10: CVE lookups (OSV.dev + WPScan)', '🛡️');
  const cveStart = Date.now();

  for (const lib of libraries) {
    if (!lib.version) continue;
    const pkgName = npmPackageNameFor(lib.name);
    if (!pkgName) continue;
    const result = await osvLookup(pkgName, lib.version);
    if (result.vulns?.length) {
      vulnResults.push({ component: `${lib.name}@${lib.version}`, source: 'OSV.dev', vulns: result.vulns });
      for (const v of result.vulns) addFinding({ category: 'cve', severity: 'high', title: `Known vulnerability in ${lib.name} ${lib.version}: ${v.id}`, detail: v.summary || v.url, url: v.url });
    }
  }

  if (primaryPlatform === 'WordPress') {
    if (!wpscanApiKey) {
      statusMsg('⏭', c.dim, 'No WPSCAN_API_KEY set — skipping live WordPress CVE lookups (core/plugin/theme version + EOL heuristics still reported).');
    } else {
      if (wpCore.version) {
        const coreRes = await wpscanCoreLookup(wpCore.version, wpscanApiKey);
        if (coreRes.vulns?.length) {
          vulnResults.push({ component: `WordPress core ${wpCore.version}`, source: 'WPScan', vulns: coreRes.vulns });
          for (const v of coreRes.vulns) addFinding({ category: 'cve', severity: 'critical', title: `WordPress core ${wpCore.version}: ${v.title}`, detail: v.fixedIn ? `Fixed in ${v.fixedIn}.` : 'No fix version listed.', url: Array.isArray(v.references) ? v.references[0] : String(v.references || '') });
        }
        if (coreRes.error) statusMsg('⚠', c.brightYellow, `WPScan core lookup: ${coreRes.error}`);
      }
      for (const p of wpPlugins) {
        const res = await wpscanPluginLookup(p.slug, wpscanApiKey);
        if (res.vulns?.length) {
          const applicable = p.version ? res.vulns.filter((v) => !v.fixedIn || semverLt(p.version, v.fixedIn)) : res.vulns;
          if (applicable.length) {
            vulnResults.push({ component: `plugin:${p.slug}@${p.version || 'unknown'}`, source: 'WPScan', vulns: applicable });
            for (const v of applicable) addFinding({ category: 'cve', severity: p.version ? 'critical' : 'medium', title: `WP plugin "${p.slug}": ${v.title}`, detail: `${p.version ? `Installed: ${p.version}. ` : 'Version undetected — verify manually. '}${v.fixedIn ? `Fixed in ${v.fixedIn}.` : ''}`, url: Array.isArray(v.references) ? v.references[0] : String(v.references || '') });
          }
        }
        await sleep(250); // stay well under WPScan free-tier rate limit
      }
      for (const t of wpThemes) {
        const res = await wpscanThemeLookup(t.slug, wpscanApiKey);
        if (res.vulns?.length) {
          const applicable = t.version ? res.vulns.filter((v) => !v.fixedIn || semverLt(t.version, v.fixedIn)) : res.vulns;
          if (applicable.length) {
            vulnResults.push({ component: `theme:${t.slug}@${t.version || 'unknown'}`, source: 'WPScan', vulns: applicable });
            for (const v of applicable) addFinding({ category: 'cve', severity: t.version ? 'high' : 'medium', title: `WP theme "${t.slug}": ${v.title}`, detail: `${t.version ? `Installed: ${t.version}. ` : 'Version undetected — verify manually. '}${v.fixedIn ? `Fixed in ${v.fixedIn}.` : ''}`, url: Array.isArray(v.references) ? v.references[0] : String(v.references || '') });
          }
        }
        await sleep(250);
      }
    }
  }
  statusMsg('🛡️', c.dim, `${vulnResults.length} component(s) with known vulnerabilities found.`);
  phaseDone('CVE lookups', Date.now() - cveStart);
} else {
  statusMsg('⏭', c.dim, 'Skipping CVE lookups (--skip-cve).');
}

// ── Phase 11: Authenticated admin audit (WordPress wp-admin, when credentials are supplied) ──
let wpAdminAudit = null;
if (!skipAdminAudit && primaryPlatform === 'WordPress' && authSettings.formAuth) {
  phaseHeader('Phase 11: Authenticated admin audit', '🔑');
  const adminStart = Date.now();
  const adminPage = await context.newPage();
  const loggedIn = await maybePerformFormLogin(adminPage, authSettings.formAuth, slowMode);
  if (loggedIn && await isLoggedIntoWpAdmin(adminPage, origin)) {
    const [plugins, themes, coreInfo, users] = await Promise.all([
      scanWpPlugins(adminPage, origin),
      scanWpThemes(adminPage, origin),
      scanWpCoreAndPhp(adminPage, origin),
      scanWpUsers(adminPage, origin),
    ]);
    const securityPlugins = detectSecurityPlugins(plugins);
    const phpIsEol = checkPhpEol(coreInfo.phpVersion);
    const admins = users.filter((u) => /administrator/i.test(u.role));

    statusMsg('🔑', c.brightGreen, `Logged in — WP ${coreInfo.wpVersion || 'unknown'}, PHP ${coreInfo.phpVersion || 'unknown'}, ${plugins.length} plugin(s), ${themes.length} theme(s), ${users.length} user(s).`);

    const outdatedPlugins = plugins.filter((p) => p.updateAvailable);
    for (const p of outdatedPlugins) addFinding({ category: 'admin-audit', severity: p.active ? 'high' : 'medium', title: `Plugin "${p.name}" has an update available (${p.version || '?'} → ${p.updateToVersion || 'newer'})`, detail: p.active ? 'Active plugin running an outdated version — check the changelog for security fixes.' : 'Inactive but still present on disk; outdated inactive plugins are still a risk if reactivated or directly reachable.', url: `${origin}/wp-admin/plugins.php` });
    const outdatedThemes = themes.filter((t) => t.updateAvailable);
    for (const t of outdatedThemes) addFinding({ category: 'admin-audit', severity: t.active ? 'medium' : 'low', title: `Theme "${t.name}" has an update available (${t.version || '?'} → ${t.updateToVersion || 'newer'})`, detail: t.active ? 'Active theme running an outdated version.' : 'Inactive theme, lower priority but still worth updating or removing.', url: `${origin}/wp-admin/themes.php` });
    if (!securityPlugins.length) addFinding({ category: 'admin-audit', severity: 'medium', title: 'No recognized security plugin is active', detail: 'No active plugin matched known security-plugin signatures (Wordfence, Sucuri, iThemes/SolidWP Security, All In One WP Security, Shield Security, etc.) — consider adding a WAF/hardening plugin.', url: `${origin}/wp-admin/plugins.php` });
    if (phpIsEol) addFinding({ category: 'admin-audit', severity: 'high', title: `PHP ${coreInfo.phpVersion} is end-of-life`, detail: 'This PHP version no longer receives security patches from php.net — upgrade to a supported version.', url: `${origin}/wp-admin/site-health.php?tab=debug` });
    if (admins.length > 3) addFinding({ category: 'admin-audit', severity: 'low', title: `${admins.length} users hold the Administrator role`, detail: `Administrators: ${admins.map((u) => u.username).join(', ')}. Review whether all of these need full admin access (principle of least privilege).`, url: `${origin}/wp-admin/users.php` });
    if (users.some((u) => u.username.toLowerCase() === 'admin')) addFinding({ category: 'admin-audit', severity: 'medium', title: 'A user account is literally named "admin"', detail: 'A username of "admin" is the first guess in any credential-stuffing/brute-force attempt — rename or remove this account.', url: `${origin}/wp-admin/users.php` });

    wpAdminAudit = { coreVersion: coreInfo.wpVersion, phpVersion: coreInfo.phpVersion, phpIsEol, mysqlVersion: coreInfo.mysqlVersion, plugins, themes, users, securityPlugins };
  } else {
    statusMsg('⚠', c.brightYellow, 'Form login did not reach wp-admin — check credentials/selectors. Skipping authenticated admin audit.');
  }
  await adminPage.close();
  phaseDone('Authenticated admin audit', Date.now() - adminStart);
} else if (authSettings.formAuth && primaryPlatform !== 'WordPress') {
  statusMsg('⏭', c.dim, `Authenticated admin audit is currently WordPress-only; detected platform is "${primaryPlatform}".`);
}

// ── Phase 12: Payment/donation summary ───────────────────────────────────
const allPaymentProcessors = new Set();
let anyCardInputForm = false;
for (const pr of pageResults) {
  for (const proc of pr.payments.processors) allPaymentProcessors.add(proc);
  if (pr.payments.hasCardInputForm) anyCardInputForm = true;
}
if (anyCardInputForm && ![...allPaymentProcessors].some((p) => ['Stripe', 'Square', 'Braintree', 'Authorize.Net'].includes(p))) {
  addFinding({ category: 'payment', severity: 'high', title: 'Card-number input field found without a recognized PCI-tokenizing processor', detail: 'Verify this form is not collecting/submitting raw card numbers to your own server.', url: site });
}
if (allPaymentProcessors.size) {
  addFinding({ category: 'payment', severity: 'info', title: `Payment/donation processor(s) detected: ${[...allPaymentProcessors].join(', ')}`, detail: 'Confirm PCI-DSS scope and that no raw card data touches your own servers.', url: site });
}

// ── Phase 13: Recon-phase pentest checks ──────────────────────────────────
let reconFindings = [];
if (!skipRecon) {
  phaseHeader('Phase 13: Recon-phase checks', '🕵️');
  const reconStart = Date.now();

  const takeovers = await checkSubdomainTakeover(hostname);
  for (const t of takeovers) addFinding({ category: 'subdomain-takeover', severity: 'critical', title: `Possible subdomain takeover: ${t.host}`, detail: t.note, url: `http://${t.host}/` });

  const httpMethods = await checkHttpMethods(site);
  if (httpMethods.checked && httpMethods.risky.length) addFinding({ category: 'http-methods', severity: 'medium', title: `Risky HTTP method(s) allowed: ${httpMethods.risky.join(', ')}`, detail: `Full Allow list: ${httpMethods.methods.join(', ') || '(none advertised)'}`, url: site });

  const openRedirects = await checkOpenRedirect(origin);
  for (const r of openRedirects) addFinding({ category: 'open-redirect', severity: 'medium', title: `Open redirect via "${r.param}" parameter`, detail: `Redirects to attacker-controlled URL: ${r.location}`, url: r.testUrl });

  const sourceMaps = await checkExposedSourceMaps(allScriptUrls);
  if (sourceMaps.length) addFinding({ category: 'source-map', severity: 'low', title: `${sourceMaps.length} exposed source map(s) (.js.map)`, detail: `Source maps can reveal original (unminified) source code. Examples: ${sourceMaps.slice(0, 3).join(', ')}`, url: sourceMaps[0] });

  const emailAuth = await checkEmailAuthRecords(hostname, dnsRecords.txt || []);
  if (!emailAuth.hasSpf) addFinding({ category: 'email-auth', severity: 'low', title: 'No SPF record found', detail: 'Without SPF, attackers can more easily spoof email "From" addresses on this domain.', url: `dns:${hostname}` });
  if (!emailAuth.hasDmarc) addFinding({ category: 'email-auth', severity: 'low', title: 'No DMARC record found', detail: 'Without DMARC, spoofed/phishing email using this domain is not rejected or reported.', url: `dns:_dmarc.${hostname}` });
  else if (emailAuth.dmarcPolicy === 'none') addFinding({ category: 'email-auth', severity: 'info', title: 'DMARC policy is "p=none" (monitor-only)', detail: 'DMARC is present but not enforcing rejection/quarantine of spoofed mail.', url: `dns:_dmarc.${hostname}` });

  if (primaryPlatform === 'WordPress') {
    const authors = await enumerateWpAuthors(origin);
    if (authors.length) addFinding({ category: 'user-enum', severity: 'medium', title: `${authors.length} WordPress username(s) enumerable via ?author=N`, detail: authors.map((a) => `id ${a.id} → ${a.username}`).join(', '), url: `${origin}/?author=1` });
  }

  const verboseErrors = await checkVerboseErrors(origin);
  if (verboseErrors.checked && verboseErrors.leaksStackTrace) addFinding({ category: 'verbose-errors', severity: 'medium', title: 'Error pages leak stack traces / framework debug info', detail: `Sample: "${verboseErrors.sample.replace(/\s+/g, ' ').slice(0, 200)}"`, url: origin });

  reconFindings = [...takeovers, ...openRedirects, ...sourceMaps];
  statusMsg('🕵️', c.dim, `Recon checks complete: ${takeovers.length} takeover signal(s), ${openRedirects.length} open redirect(s), ${sourceMaps.length} exposed source map(s).`);
  phaseDone('Recon-phase checks', Date.now() - reconStart);
} else {
  statusMsg('⏭', c.dim, 'Skipping recon-phase checks (--skip-recon).');
}

// ── Phase 14: Risk scoring + report generation ───────────────────────────
phaseHeader('Phase 14: Report generation', '📝');
const reportStart = Date.now();
const sorted = sortFindingsBySeverity(findings);
const risk = computeRiskGrade(findings);

writeCsv(path.join(outDir, 'findings-summary.csv'), ['category', 'severity', 'title', 'detail', 'url'], sorted);
writeCsv(path.join(outDir, 'exposed-paths.csv'), ['path', 'label', 'status', 'exists', 'directoryListing', 'severity', 'url'], pathResults);
writeCsv(path.join(outDir, 'script-inventory.csv'), ['name', 'version', 'sourceUrl'], libraries);
if (primaryPlatform === 'WordPress') {
  writeCsv(path.join(outDir, 'wordpress-components.csv'), ['type', 'slug', 'version', 'sourceUrl'], [
    ...wpPlugins.map((p) => ({ type: 'plugin', ...p })),
    ...wpThemes.map((t) => ({ type: 'theme', ...t })),
  ]);
}
writeCsv(path.join(outDir, 'vulnerabilities.csv'), ['component', 'source', 'id', 'title'], vulnResults.flatMap((r) => r.vulns.map((v) => ({ component: r.component, source: r.source, id: v.id, title: v.title || v.summary || '' }))));
writeCsv(path.join(outDir, 'port-scan.csv'), ['port', 'name', 'state', 'banner'], portResults);
if (discoveredSubdomains.length) writeCsv(path.join(outDir, 'subdomains.csv'), ['subdomain'], discoveredSubdomains.map((s) => ({ subdomain: s })));
if (wpAdminAudit) {
  writeCsv(path.join(outDir, 'wp-admin-plugins.csv'), ['slug', 'name', 'active', 'version', 'updateAvailable', 'updateToVersion'], wpAdminAudit.plugins);
  writeCsv(path.join(outDir, 'wp-admin-themes.csv'), ['slug', 'name', 'active', 'version', 'updateAvailable', 'updateToVersion'], wpAdminAudit.themes);
  writeCsv(path.join(outDir, 'wp-admin-users.csv'), ['username', 'role'], wpAdminAudit.users);
}
const generatedAt = new Date().toISOString();
const summaryData = {
  site, generatedAt, risk, primaryPlatform, platformSignals, hostingSignals, dnsRecords,
  tls: tlsInfo, crawlerExposure, paymentProcessors: [...allPaymentProcessors],
  whois: whois.checked ? whois : null,
  subdomains: discoveredSubdomains,
  openPorts: portResults.filter((r) => r.state === 'open'),
  wpAdminAudit,
};
fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify(summaryData, null, 2), 'utf8');

const fullReport = { ...summaryData, findings: sorted, vulnerabilities: vulnResults, exposedPaths: pathResults, libraries };
fs.writeFileSync(path.join(outDir, 'full-report.json'), JSON.stringify(fullReport, null, 2), 'utf8');
if (jsonOut) console.log(JSON.stringify(fullReport, null, 2));

const dashboardHtml = buildSecurityDashboardHtml({ site, risk, sorted, primaryPlatform, platformSignals, hostingSignals, tlsInfo, dnsRecords, libraries, vulnResults, crawlerExposure, paymentProcessors: [...allPaymentProcessors], generatedAt }, branding);
fs.writeFileSync(path.join(outDir, 'security-dashboard.html'), dashboardHtml, 'utf8');
try {
  const reportPage = await context.newPage();
  await reportPage.goto('file://' + path.join(outDir, 'security-dashboard.html'));
  await reportPage.pdf({ path: path.join(outDir, 'security-dashboard.pdf'), format: 'A4', printBackground: true, margin: { top: '20px', bottom: '20px', left: '20px', right: '20px' } });
  await reportPage.close();
  out(`Wrote: ${path.join(outDir, 'security-dashboard.pdf')}`);
} catch (e) {
  statusMsg('⚠', c.brightYellow, `PDF generation failed: ${String(e?.message || e)}`);
}
out(`Wrote: ${path.join(outDir, 'security-dashboard.html')}`);
phaseDone('Report generation', Date.now() - reportStart);

await context.close();
await browser.close();

out('');
out(`  ${rainbow('╔══════════════════════════════════════════════════════════╗')}`);
out(`  ${rainbow('║')}  ${c.bold}✨ Security Audit Complete!${c.reset}                          ${rainbow('║')}`);
out(`  ${rainbow('╚══════════════════════════════════════════════════════════╝')}`);
out('');
out(`  🎯 Site           ${site}`);
out(`  🧩 Platform       ${primaryPlatform}`);
out(`  🏆 Risk grade     ${risk.grade} (${risk.score}/100)`);
out(`  🔴 Critical       ${risk.counts.critical}`);
out(`  🟠 High           ${risk.counts.high}`);
out(`  🟡 Medium         ${risk.counts.medium}`);
out(`  🔵 Low            ${risk.counts.low}`);
out(`  ⚪ Info           ${risk.counts.info}`);
out(`  ⏱️  Time           ${formatDuration(Date.now() - auditStart)}`);
out(`  📁 Output         ${outDir}`);
out('');

// ── CI/CD gating: exit non-zero if requested severity/grade thresholds are breached ──
let ciFailed = false;
if (failOn && hasFindingAtOrAbove(findings, failOn)) {
  statusMsg('✖', c.brightRed, `--fail-on ${failOn}: at least one finding at or above "${failOn}" severity was found.`);
  ciFailed = true;
}
if (minGrade && isGradeBelow(risk.grade, minGrade)) {
  statusMsg('✖', c.brightRed, `--min-grade ${minGrade}: risk grade ${risk.grade} is below the required threshold.`);
  ciFailed = true;
}
if (ciFailed) process.exitCode = 1;
