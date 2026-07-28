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
import { computeRiskGrade, sortFindingsBySeverity } from './lib/scoring.mjs';

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
function phaseHeader(label, icon = '▸') {
  console.log('');
  console.log(`  ${rainbow(icon)} ${c.bold}${c.brightCyan}${label}${c.reset} ${c.dim}${'─'.repeat(Math.max(0, 52 - label.length))}${c.reset}`);
}
function phaseDone(label, elapsed) { console.log(`    ${c.brightGreen}✔${c.reset} ${label} ${c.dim}in${c.reset} ${c.brightYellow}${formatDuration(elapsed)}${c.reset}`); }
function statusMsg(icon, color, msg) { console.log(`    ${color}${icon}${c.reset} ${msg}`); }
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
const wpscanApiKey = args['wpscan-key'] || process.env.WPSCAN_API_KEY || '';
const outDir = path.resolve('reports/' + runId(site));
fs.mkdirSync(outDir, { recursive: true });

const auditStart = Date.now();
console.log('');
console.log(`  ${rainbow('╔══════════════════════════════════════════════════════════╗')}`);
console.log(`  ${rainbow('║')}  ${c.bold}${c.brightRed}🛡  Universal Security Audit${c.reset}                          ${rainbow('║')}`);
console.log(`  ${rainbow('║')}  ${c.dim}Attack Surface · Headers · CVEs · PII · Payments${c.reset}       ${rainbow('║')}`);
console.log(`  ${rainbow('╚══════════════════════════════════════════════════════════╝')}`);
console.log('');
console.log(`  ${c.brightMagenta}🎯${c.reset} ${c.bold}Target:${c.reset}     ${c.brightCyan}${site}${c.reset}`);
console.log(`  ${c.brightMagenta}📁${c.reset} ${c.bold}Output:${c.reset}     ${c.dim}${outDir}${c.reset}`);
console.log(`  ${c.brightMagenta}🔑${c.reset} ${c.bold}WPScan key:${c.reset} ${wpscanApiKey ? `${c.brightGreen}configured${c.reset}` : `${c.dim}not set (WordPress CVE lookups will be skipped)${c.reset}`}`);
statusMsg('⚠', c.brightYellow, 'Authorized-use only — this tool actively probes admin/config paths. Only run it against sites you own or have written permission to test.');

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
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ userAgent: 'Mozilla/5.0 (compatible; Universal-Security-Audit/1.0)' });
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

// ── Phase 4: Exposed path / admin / API discovery ───────────────────────
let pathResults = [];
if (!skipExposedPaths) {
  phaseHeader('Phase 4: Exposed path & admin/API discovery', '🔎');
  const pathStart = Date.now();
  const allPaths = [...ADMIN_LOGIN_PATHS, ...EXPOSED_FILE_PATHS, ...EXPOSED_API_PATHS];
  pathResults = await probeAllPaths(origin, allPaths, { isAllowedUrl: respectRobots ? robotsCfg.isAllowedUrl : null, delayMs: slowMode ? 400 : 150 });
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

// ── Phase 5: Page scanning (platform fingerprint, script inventory, PII, payments) ──
phaseHeader('Phase 5: Page scanning', '📄');
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

    if (pii.secrets.length) {
      for (const s of pii.secrets) addFinding({ category: 'pii', severity: 'critical', title: `Exposed ${s.type} in page source`, detail: `${s.count} occurrence(s), e.g. "${s.sample}"`, url });
    }
    if (pii.ssnLike.length) addFinding({ category: 'pii', severity: 'high', title: 'SSN-like number(s) found in page content', detail: `${pii.ssnLike.length} match(es).`, url });
    if (pii.cardLike.length) addFinding({ category: 'pii', severity: 'critical', title: 'Credit-card-like number(s) found in page content', detail: `${pii.cardLike.length} Luhn-valid match(es): ${pii.cardLike.slice(0, 3).join(', ')}`, url });
    if (pii.emails.length) addFinding({ category: 'pii', severity: 'info', title: `${pii.emails.length} email address(es) exposed on page`, detail: pii.emails.slice(0, 5).join(', '), url });
    if (mixed.applicable && mixed.refs.length) addFinding({ category: 'mixed-content', severity: 'medium', title: `${mixed.refs.length} mixed-content (http://) resource(s) on HTTPS page`, detail: mixed.refs.slice(0, 5).join(', '), url });

    pageResults.push({ url, platformSignals, pii, payments, mixed });
    statusMsg('✔', c.brightGreen, `[${i + 1}/${pageUrls.length}] ${url}`);
  } catch (e) {
    statusMsg('✖', c.brightRed, `[${i + 1}/${pageUrls.length}] ${url} — ${String(e?.message || e)}`);
  } finally {
    await page.close();
  }
}
phaseDone('Page scanning', Date.now() - scanStart);

// ── Phase 6: Platform + third-party library inventory ──────────────────
phaseHeader('Phase 6: Platform & library inventory', '📦');
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

// ── Phase 7: CVE / known-vulnerability lookups (OSV.dev + WPScan) ───────
const vulnResults = [];
if (!skipCve) {
  phaseHeader('Phase 7: CVE lookups (OSV.dev + WPScan)', '🛡️');
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

// ── Phase 8: Payment/donation summary ───────────────────────────────────
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

// ── Phase 9: Risk scoring + report generation ───────────────────────────
phaseHeader('Phase 9: Report generation', '📝');
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
fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify({
  site, generatedAt: new Date().toISOString(), risk, primaryPlatform, hostingSignals, dnsRecords,
  tls: tlsInfo, crawlerExposure, paymentProcessors: [...allPaymentProcessors],
}, null, 2), 'utf8');

const dashboardHtml = buildDashboardHtml({ site, risk, sorted, primaryPlatform, platformSignals, hostingSignals, tlsInfo, dnsRecords, libraries, vulnResults, crawlerExposure, paymentProcessors: [...allPaymentProcessors] });
fs.writeFileSync(path.join(outDir, 'security-dashboard.html'), dashboardHtml, 'utf8');
try {
  const reportPage = await context.newPage();
  await reportPage.goto('file://' + path.join(outDir, 'security-dashboard.html'));
  await reportPage.pdf({ path: path.join(outDir, 'security-dashboard.pdf'), format: 'A4', printBackground: true, margin: { top: '20px', bottom: '20px', left: '20px', right: '20px' } });
  await reportPage.close();
  console.log(`Wrote: ${path.join(outDir, 'security-dashboard.pdf')}`);
} catch (e) {
  statusMsg('⚠', c.brightYellow, `PDF generation failed: ${String(e?.message || e)}`);
}
console.log(`Wrote: ${path.join(outDir, 'security-dashboard.html')}`);
phaseDone('Report generation', Date.now() - reportStart);

await context.close();
await browser.close();

console.log('');
console.log(`  ${rainbow('╔══════════════════════════════════════════════════════════╗')}`);
console.log(`  ${rainbow('║')}  ${c.bold}✨ Security Audit Complete!${c.reset}                          ${rainbow('║')}`);
console.log(`  ${rainbow('╚══════════════════════════════════════════════════════════╝')}`);
console.log('');
console.log(`  🎯 Site           ${site}`);
console.log(`  🧩 Platform       ${primaryPlatform}`);
console.log(`  🏆 Risk grade     ${risk.grade} (${risk.score}/100)`);
console.log(`  🔴 Critical       ${risk.counts.critical}`);
console.log(`  🟠 High           ${risk.counts.high}`);
console.log(`  🟡 Medium         ${risk.counts.medium}`);
console.log(`  🔵 Low            ${risk.counts.low}`);
console.log(`  ⚪ Info           ${risk.counts.info}`);
console.log(`  ⏱️  Time           ${formatDuration(Date.now() - auditStart)}`);
console.log(`  📁 Output         ${outDir}`);
console.log('');

// ── Dashboard HTML builder ───────────────────────────────────────────────
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])); }
function buildDashboardHtml({ site, risk, sorted, primaryPlatform, platformSignals, hostingSignals, tlsInfo, dnsRecords, libraries, vulnResults, crawlerExposure, paymentProcessors }) {
  const gradeColor = { 'A+': '#16a34a', A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' }[risk.grade] || '#94a3b8';
  const sevColorMap = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#94a3b8' };
  const rows = sorted.map((f) => `
    <tr>
      <td><span class="badge" style="background:${sevColorMap[f.severity]}22;color:${sevColorMap[f.severity]}">${esc(f.severity)}</span></td>
      <td>${esc(f.category)}</td>
      <td>${esc(f.title)}</td>
      <td class="detail">${esc(f.detail)}</td>
      <td class="url">${f.url ? `<a href="${esc(f.url)}" target="_blank" rel="noopener">${esc(f.url)}</a>` : ''}</td>
    </tr>`).join('');
  const vulnRows = vulnResults.flatMap((r) => r.vulns.map((v) => `
    <tr><td>${esc(r.component)}</td><td>${esc(r.source)}</td><td>${esc(v.id || '')}</td><td>${esc(v.title || v.summary || '')}</td></tr>`)).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Security Audit — ${esc(site)}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 2rem; background: #0b0f16; color: #e2e8f0; }
  h1 { font-size: 1.4rem; margin-bottom: .25rem; }
  .sub { color: #94a3b8; margin-bottom: 1.5rem; }
  .grade-card { display: inline-flex; align-items: center; gap: 1rem; background: #131a24; border: 1px solid #1f2937; border-radius: 12px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }
  .grade { font-size: 2.5rem; font-weight: 800; color: ${gradeColor}; }
  .stats { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .stat { background: #131a24; border: 1px solid #1f2937; border-radius: 10px; padding: .75rem 1rem; min-width: 110px; }
  .stat .n { font-size: 1.4rem; font-weight: 700; }
  .stat .l { font-size: .75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; }
  section { margin-bottom: 2rem; }
  table { width: 100%; border-collapse: collapse; background: #131a24; border: 1px solid #1f2937; border-radius: 10px; overflow: hidden; }
  th, td { text-align: left; padding: .6rem .8rem; border-bottom: 1px solid #1f2937; font-size: .85rem; vertical-align: top; }
  th { background: #1a2230; color: #94a3b8; text-transform: uppercase; font-size: .7rem; letter-spacing: .05em; }
  .badge { padding: .15rem .5rem; border-radius: 999px; font-size: .7rem; font-weight: 700; text-transform: uppercase; }
  .detail { color: #cbd5e1; max-width: 420px; }
  .url a { color: #60a5fa; word-break: break-all; }
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap: 1rem; }
  .meta-card { background: #131a24; border: 1px solid #1f2937; border-radius: 10px; padding: 1rem; }
  .meta-card h3 { margin: 0 0 .5rem; font-size: .8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; }
  code { background: #1a2230; padding: .1rem .35rem; border-radius: 4px; }
  @media (prefers-color-scheme: light) {
    body { background: #f8fafc; color: #0f172a; }
    .grade-card, .stat, table, .meta-card { background: #fff; border-color: #e2e8f0; }
    th { background: #f1f5f9; }
    .detail { color: #334155; }
  }
</style></head><body>
  <h1>🛡️ Universal Security Audit</h1>
  <div class="sub">${esc(site)} · generated ${new Date().toLocaleString()}</div>
  <div class="grade-card"><div class="grade">${risk.grade}</div><div><div style="font-weight:600">${risk.score}/100 risk score</div><div style="color:#94a3b8;font-size:.85rem">${risk.total} finding(s) across all checks</div></div></div>
  <div class="stats">
    <div class="stat"><div class="n" style="color:${sevColorMap.critical}">${risk.counts.critical}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:${sevColorMap.high}">${risk.counts.high}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:${sevColorMap.medium}">${risk.counts.medium}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:${sevColorMap.low}">${risk.counts.low}</div><div class="l">Low</div></div>
    <div class="stat"><div class="n" style="color:${sevColorMap.info}">${risk.counts.info}</div><div class="l">Info</div></div>
  </div>
  <section>
    <div class="meta-grid">
      <div class="meta-card"><h3>Platform</h3>${platformSignals.map((s) => `<div>${esc(s.platform)} <span style="color:#94a3b8">(${esc(s.confidence)})</span></div>`).join('')}</div>
      <div class="meta-card"><h3>Hosting / CDN</h3>${hostingSignals.length ? hostingSignals.map((h) => `<div>${esc(h.provider)}</div>`).join('') : '<div style="color:#94a3b8">No signals detected</div>'}</div>
      <div class="meta-card"><h3>TLS</h3>${tlsInfo.ok ? `<div>${esc(tlsInfo.protocol)}</div><div>Expires in ${tlsInfo.daysRemaining}d</div><div>Issuer: ${esc(tlsInfo.issuer)}</div>` : '<div style="color:#94a3b8">Not checked / unavailable</div>'}</div>
      <div class="meta-card"><h3>DNS</h3><div>A: ${esc((dnsRecords.a || []).join(', ') || '—')}</div><div>NS: ${esc((dnsRecords.ns || []).join(', ') || '—')}</div><div>MX: ${esc((dnsRecords.mx || []).join(', ') || '—')}</div></div>
      <div class="meta-card"><h3>Crawler exposure</h3><div>robots.txt: ${crawlerExposure.hasRobots ? 'yes' : 'no'}</div><div>llms.txt: ${crawlerExposure.hasLlmsTxt ? 'yes' : 'no'}</div><div>sitemap: ${crawlerExposure.hasSitemap ? 'yes' : 'no'}</div></div>
      <div class="meta-card"><h3>Payment/donation</h3>${paymentProcessors.length ? paymentProcessors.map((p) => `<div>${esc(p)}</div>`).join('') : '<div style="color:#94a3b8">None detected</div>'}</div>
    </div>
  </section>
  <section>
    <h2>Findings</h2>
    <table><thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Detail</th><th>URL</th></tr></thead><tbody>${rows || '<tr><td colspan="5" style="text-align:center;color:#94a3b8">No findings 🎉</td></tr>'}</tbody></table>
  </section>
  ${vulnRows ? `<section><h2>Known Vulnerabilities (OSV.dev / WPScan)</h2><table><thead><tr><th>Component</th><th>Source</th><th>ID</th><th>Title</th></tr></thead><tbody>${vulnRows}</tbody></table></section>` : ''}
  <section><h3>Detected libraries</h3><table><thead><tr><th>Name</th><th>Version</th><th>Source</th></tr></thead><tbody>${libraries.map((l) => `<tr><td>${esc(l.name)}</td><td>${esc(l.version || 'unknown')}</td><td class="url">${esc(l.sourceUrl)}</td></tr>`).join('') || '<tr><td colspan="3" style="text-align:center;color:#94a3b8">None detected</td></tr>'}</tbody></table></section>
</body></html>`;
}
