#!/usr/bin/env node
// Runs the full security audit across a list of sites, aggregating a summary table. Each site still
// gets its own normal reports/<site>-<timestamp>/ directory with all the usual CSVs/HTML/PDF — this
// just adds a rollup on top by running each child with --json and parsing its clean stdout.
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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
function esc(s) { s = String(s ?? ''); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
function writeCsv(rows, columns, outPath) {
  const body = [columns.join(','), ...rows.map((r) => columns.map((c) => esc(r[c])).join(','))].join('\n') + '\n';
  fs.writeFileSync(outPath, body, 'utf8');
}

const args = parseArgs(process.argv);
if (!args['sites-file']) { console.error('Missing --sites-file'); process.exit(1); }
const sitesFile = path.resolve(process.cwd(), args['sites-file']);
const sites = fs.readFileSync(sitesFile, 'utf8').split(/\r?\n/g).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
if (!sites.length) { console.error('No sites found in --sites-file'); process.exit(1); }

const concurrency = args.concurrency ? Number(args.concurrency) : 1;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const auditScript = path.join(__dirname, 'run-security-audit.mjs');

// Everything except our own batch-only flags gets forwarded to each child audit run.
const OWN_FLAGS = new Set(['sites-file', 'concurrency', 'out-dir']);
const passthrough = [];
for (const [key, val] of Object.entries(args)) {
  if (OWN_FLAGS.has(key)) continue;
  passthrough.push(`--${key}`);
  if (val !== true) passthrough.push(String(val));
}

function runOne(site) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [auditScript, '--site', site, '--json', ...passthrough], { stdio: ['ignore', 'pipe', 'inherit'] });
    let stdout = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.on('close', (code) => {
      let report = null;
      try { report = JSON.parse(stdout); } catch {}
      resolve({ site, exitCode: code, report });
    });
  });
}

console.log(`Running batch audit across ${sites.length} site(s) (concurrency ${concurrency})...`);
const results = [];
const queue = [...sites];
async function worker() {
  while (queue.length) {
    const site = queue.shift();
    console.log(`→ ${site}`);
    results.push(await runOne(site));
  }
}
await Promise.all(Array.from({ length: Math.min(concurrency, sites.length) }, worker));

const outDir = args['out-dir'] ? path.resolve(process.cwd(), args['out-dir']) : path.resolve('reports');
fs.mkdirSync(outDir, { recursive: true });
const batchId = Date.now();

const rows = results.map((r) => ({
  site: r.site,
  status: r.report ? 'completed' : 'failed',
  platform: r.report?.primaryPlatform || '',
  grade: r.report?.risk?.grade || '',
  score: r.report?.risk?.score ?? '',
  critical: r.report?.risk?.counts?.critical ?? '',
  high: r.report?.risk?.counts?.high ?? '',
  medium: r.report?.risk?.counts?.medium ?? '',
  low: r.report?.risk?.counts?.low ?? '',
  info: r.report?.risk?.counts?.info ?? '',
  exitCode: r.exitCode,
}));
rows.sort((a, b) => (a.score === '' ? 999 : a.score) - (b.score === '' ? 999 : b.score));

const csvPath = path.join(outDir, `batch-summary-${batchId}.csv`);
writeCsv(rows, ['site', 'status', 'platform', 'grade', 'score', 'critical', 'high', 'medium', 'low', 'info', 'exitCode'], csvPath);

const failed = rows.filter((r) => r.status === 'failed');
const md = [
  '# Batch Security Audit Summary', '',
  `Sites scanned: ${sites.length} · Completed: ${rows.length - failed.length} · Failed: ${failed.length}`, '',
  '| Site | Grade | Score | Critical | High | Medium | Low | Info |',
  '| --- | --- | --- | --- | --- | --- | --- | --- |',
  ...rows.map((r) => `| ${r.site} | ${r.grade} | ${r.score} | ${r.critical} | ${r.high} | ${r.medium} | ${r.low} | ${r.info} |`),
].join('\n');
const mdPath = path.join(outDir, `batch-summary-${batchId}.md`);
fs.writeFileSync(mdPath, md, 'utf8');

console.log('');
console.log(`Wrote: ${csvPath}`);
console.log(`Wrote: ${mdPath}`);
if (failed.length) {
  console.error(`${failed.length} site(s) failed: ${failed.map((f) => f.site).join(', ')}`);
  process.exitCode = 1;
}
