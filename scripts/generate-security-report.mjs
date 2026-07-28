#!/usr/bin/env node
// Standalone report regenerator — rebuilds security-dashboard.html/.pdf from an existing run's
// summary.json + CSVs without re-scanning the site. Useful for re-branding a past run or fixing
// a report after a dashboard template change. Mirrors universal-seo-audit's
// generate-visual-report.mjs --run-dir convention.
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';
import { loadBranding, buildSecurityDashboardHtml } from './lib/report-builder.mjs';
import { sortFindingsBySeverity, computeRiskGrade } from './lib/scoring.mjs';

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
function parseCsv(csvText) {
  const rows = [];
  let row = [], field = '', inQuotes = false;
  const pushField = () => { row.push(field); field = ''; };
  const pushRow = () => { if (!(row.length === 1 && row[0] === '')) rows.push(row); row = []; };
  for (let i = 0; i < csvText.length; i++) {
    const ch = csvText[i];
    if (inQuotes) {
      if (ch === '"') { if (csvText[i + 1] === '"') { field += '"'; i++; } else inQuotes = false; }
      else field += ch;
      continue;
    }
    if (ch === '"') { inQuotes = true; continue; }
    if (ch === ',') { pushField(); continue; }
    if (ch === '\n') { pushField(); pushRow(); continue; }
    if (ch === '\r') { if (csvText[i + 1] === '\n') i++; pushField(); pushRow(); continue; }
    field += ch;
  }
  pushField(); pushRow();
  if (!rows.length) return [];
  const headers = rows[0];
  return rows.slice(1).map((r) => Object.fromEntries(headers.map((h, idx) => [h, r[idx] ?? ''])));
}
function readCsvIfExists(filePath) {
  try { return parseCsv(fs.readFileSync(filePath, 'utf8')); } catch { return []; }
}

const args = parseArgs(process.argv);
if (!args['run-dir']) { console.error('Missing --run-dir'); process.exit(1); }
const runDir = path.resolve(process.cwd(), args['run-dir']);

const summary = JSON.parse(fs.readFileSync(path.join(runDir, 'summary.json'), 'utf8'));
const findingsRows = readCsvIfExists(path.join(runDir, 'findings-summary.csv'));
const libraries = readCsvIfExists(path.join(runDir, 'script-inventory.csv'));
const vulnRows = readCsvIfExists(path.join(runDir, 'vulnerabilities.csv'));

const vulnByComponent = new Map();
for (const v of vulnRows) {
  const key = `${v.component}__${v.source}`;
  if (!vulnByComponent.has(key)) vulnByComponent.set(key, { component: v.component, source: v.source, vulns: [] });
  vulnByComponent.get(key).vulns.push({ id: v.id, title: v.title });
}

const sorted = sortFindingsBySeverity(findingsRows.map((f) => ({ ...f, suppressed: f.suppressed === 'true' })));
const risk = summary.risk || computeRiskGrade(findingsRows.filter((f) => f.suppressed !== 'true'));

const branding = loadBranding(fs, path, args['brand-config']);
const site = args.site || summary.site;

const html = buildSecurityDashboardHtml({
  site,
  risk,
  sorted,
  primaryPlatform: summary.primaryPlatform,
  platformSignals: summary.platformSignals || [{ platform: summary.primaryPlatform, confidence: 'n/a' }],
  hostingSignals: summary.hostingSignals || [],
  tlsInfo: summary.tls || { ok: false },
  dnsRecords: summary.dnsRecords || {},
  libraries,
  vulnResults: [...vulnByComponent.values()],
  crawlerExposure: summary.crawlerExposure || {},
  paymentProcessors: summary.paymentProcessors || [],
  generatedAt: summary.generatedAt,
}, branding);

const htmlPath = path.join(runDir, 'security-dashboard.html');
fs.writeFileSync(htmlPath, html, 'utf8');
console.log(`Wrote: ${htmlPath}`);

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
await page.goto('file://' + htmlPath);
const pdfPath = path.join(runDir, 'security-dashboard.pdf');
await page.pdf({ path: pdfPath, format: 'A4', printBackground: true, margin: { top: '20px', bottom: '20px', left: '20px', right: '20px' } });
await browser.close();
console.log(`Wrote: ${pdfPath}`);
