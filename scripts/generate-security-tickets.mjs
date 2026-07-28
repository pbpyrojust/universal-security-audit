#!/usr/bin/env node
// Turns findings-summary.csv into a ticket-ready backlog CSV, mirroring universal-seo-audit's
// generate-seo-tickets.mjs conventions (global vs. per-URL grouping, ticket_title/description/labels).
import fs from 'node:fs';
import path from 'node:path';

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
function esc(s) { s = String(s ?? ''); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
function writeCsv(rows, columns, outPath) {
  const body = [columns.join(','), ...rows.map((r) => columns.map((c) => esc(r[c])).join(','))].join('\n') + '\n';
  fs.writeFileSync(outPath, body, 'utf8');
}

// Categories whose findings apply to the whole site (one root cause, dedupe across pages) vs.
// categories that are inherently per-page/per-URL and should stay as separate tickets.
const GLOBAL_CATEGORIES = new Set([
  'headers', 'cookies', 'tls', 'cors', 'crawler-exposure', 'subdomain-takeover',
  'http-methods', 'open-redirect', 'source-map', 'email-auth', 'user-enum',
  'verbose-errors', 'cve', 'admin-login', 'exposed-path', 'exposed-api', 'payment',
]);
const SEVERITY_PRIORITY = { critical: 'P0', high: 'P1', medium: 'P2', low: 'P3', info: 'P4' };

const args = parseArgs(process.argv);
const runDir = args['run-dir'];
if (!runDir) { console.error('ERROR: Missing --run-dir'); process.exit(1); }
const findings = parseCsv(fs.readFileSync(path.join(runDir, 'findings-summary.csv'), 'utf8'));

const globals = new Map();
const perUrl = [];
for (const f of findings) {
  if (GLOBAL_CATEGORIES.has(f.category)) {
    const key = `${f.category}__${f.title}__${f.severity}`;
    const item = globals.get(key) || { ...f, urls: new Set(), occurrences: 0 };
    item.urls.add(f.url);
    item.occurrences += 1;
    globals.set(key, item);
  } else {
    perUrl.push(f);
  }
}

const rows = [];
for (const item of globals.values()) {
  const exampleUrls = [...item.urls].slice(0, 5).join(' | ');
  const priority = SEVERITY_PRIORITY[item.severity] || 'P4';
  rows.push({
    ticket_type: 'Global',
    category: item.category,
    severity: item.severity,
    priority,
    pages_affected: item.urls.size,
    occurrences: item.occurrences,
    example_urls: exampleUrls,
    ticket_title: `[SEC][${priority}] ${item.title}`,
    ticket_description: [
      `Category: ${item.category}`,
      `Severity: ${item.severity}`,
      `Detail: ${item.detail}`,
      `URLs affected: ${item.urls.size}`,
      `Occurrences: ${item.occurrences}`,
      `Example URL(s): ${exampleUrls}`,
      '',
      'Recommended action: fix at the shared/infra level (server config, template, or plugin) rather than per-page, then re-run the audit to confirm resolution.',
    ].join('\n'),
    ticket_labels: `security, ${item.category}, priority:${priority.toLowerCase()}, global`,
  });
}
for (const f of perUrl) {
  const priority = SEVERITY_PRIORITY[f.severity] || 'P4';
  rows.push({
    ticket_type: 'Page',
    category: f.category,
    severity: f.severity,
    priority,
    pages_affected: 1,
    occurrences: 1,
    example_urls: f.url,
    ticket_title: `[SEC][${priority}] ${f.title} — ${f.url}`,
    ticket_description: [
      `Category: ${f.category}`,
      `Severity: ${f.severity}`,
      `Detail: ${f.detail}`,
      `URL: ${f.url}`,
    ].join('\n'),
    ticket_labels: `security, ${f.category}, priority:${priority.toLowerCase()}, page`,
  });
}

rows.sort((a, b) => a.priority.localeCompare(b.priority));
const outPath = path.join(runDir, 'security-ticket-backlog.csv');
writeCsv(rows, ['ticket_type', 'category', 'severity', 'priority', 'pages_affected', 'occurrences', 'example_urls', 'ticket_title', 'ticket_description', 'ticket_labels'], outPath);
console.log(`Wrote: ${outPath} (${rows.length} ticket${rows.length === 1 ? '' : 's'})`);
