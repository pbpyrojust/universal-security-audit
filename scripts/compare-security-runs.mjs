#!/usr/bin/env node
// Diffs two audit runs' findings-summary.csv + risk grade, mirroring compare-seo-runs.mjs output shape.
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
function esc(s) { s = String(s ?? ''); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
function writeCsv(rows, columns, outPath) {
  const body = [columns.join(','), ...rows.map((r) => columns.map((c) => esc(r[c])).join(','))].join('\n') + '\n';
  fs.writeFileSync(outPath, body, 'utf8');
}

const args = parseArgs(process.argv);
if (!args.before || !args.after) {
  console.error('Usage: node scripts/compare-security-runs.mjs --before reports/run-a --after reports/run-b');
  process.exit(1);
}
const beforeDir = path.resolve(process.cwd(), args.before);
const afterDir = path.resolve(process.cwd(), args.after);
const outDir = args['out-dir'] ? path.resolve(process.cwd(), args['out-dir']) : afterDir;
fs.mkdirSync(outDir, { recursive: true });

const beforeFindings = parseCsv(fs.readFileSync(path.join(beforeDir, 'findings-summary.csv'), 'utf8'));
const afterFindings = parseCsv(fs.readFileSync(path.join(afterDir, 'findings-summary.csv'), 'utf8'));
const key = (r) => `${r.category}__${r.title}__${r.url}`;
const beforeMap = new Map(beforeFindings.map((r) => [key(r), r]));
const afterMap = new Map(afterFindings.map((r) => [key(r), r]));
const newFindings = afterFindings.filter((r) => !beforeMap.has(key(r)));
const resolvedFindings = beforeFindings.filter((r) => !afterMap.has(key(r)));
const unchangedFindings = afterFindings.filter((r) => beforeMap.has(key(r)));

const countsBySeverity = (rows) => rows.reduce((acc, r) => { acc[r.severity] = (acc[r.severity] || 0) + 1; return acc; }, {});
const beforeSevCounts = countsBySeverity(beforeFindings);
const afterSevCounts = countsBySeverity(afterFindings);
const severities = ['critical', 'high', 'medium', 'low', 'info'];
const severitySummary = severities.map((sev) => ({ severity: sev, before_count: beforeSevCounts[sev] || 0, after_count: afterSevCounts[sev] || 0, delta: (afterSevCounts[sev] || 0) - (beforeSevCounts[sev] || 0) }));

let beforeRisk = null, afterRisk = null;
try { beforeRisk = JSON.parse(fs.readFileSync(path.join(beforeDir, 'summary.json'), 'utf8')).risk; } catch {}
try { afterRisk = JSON.parse(fs.readFileSync(path.join(afterDir, 'summary.json'), 'utf8')).risk; } catch {}

writeCsv(severitySummary, ['severity', 'before_count', 'after_count', 'delta'], path.join(outDir, 'security-compare-summary.csv'));
writeCsv(newFindings, Object.keys(newFindings[0] || { category: '', severity: '', title: '', detail: '', url: '' }), path.join(outDir, 'security-compare-new-findings.csv'));
writeCsv(resolvedFindings, Object.keys(resolvedFindings[0] || { category: '', severity: '', title: '', detail: '', url: '' }), path.join(outDir, 'security-compare-resolved-findings.csv'));

const md = [
  '# Security Run Comparison', '',
  `Before: ${beforeDir}`, `After: ${afterDir}`, '',
  beforeRisk && afterRisk ? `Risk grade: ${beforeRisk.grade} (${beforeRisk.score}/100) -> ${afterRisk.grade} (${afterRisk.score}/100)` : '', '',
  `New findings: ${newFindings.length}`, `Resolved findings: ${resolvedFindings.length}`, `Unchanged findings: ${unchangedFindings.length}`, '',
  '## Severity deltas', ...severitySummary.map((r) => `- ${r.severity}: ${r.before_count} -> ${r.after_count} (${r.delta >= 0 ? '+' : ''}${r.delta})`), '',
  '## New findings', ...newFindings.slice(0, 30).map((r) => `- [${r.severity}] ${r.category} — ${r.title} — ${r.url}`), '',
  '## Resolved findings', ...resolvedFindings.slice(0, 30).map((r) => `- [${r.severity}] ${r.category} — ${r.title} — ${r.url}`),
].filter((l) => l !== undefined);
fs.writeFileSync(path.join(outDir, 'security-compare-summary.md'), md.join('\n'), 'utf8');

console.log(`Wrote: ${path.join(outDir, 'security-compare-summary.csv')}`);
console.log(`Wrote: ${path.join(outDir, 'security-compare-new-findings.csv')}`);
console.log(`Wrote: ${path.join(outDir, 'security-compare-resolved-findings.csv')}`);
console.log(`Wrote: ${path.join(outDir, 'security-compare-summary.md')}`);
