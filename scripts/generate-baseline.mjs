#!/usr/bin/env node
// Snapshots every finding in a run into a baseline/exceptions file (accept-all-current), so future
// runs stop failing on already-known-and-accepted findings. Edit the output afterward to add real
// `reason` text and/or `expires` dates — this just gives you the starting fingerprints.
import fs from 'node:fs';
import path from 'node:path';
import { fingerprintFinding } from './lib/baseline.mjs';

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

const args = parseArgs(process.argv);
if (!args['run-dir']) { console.error('Missing --run-dir'); process.exit(1); }
const runDir = path.resolve(process.cwd(), args['run-dir']);
const findings = parseCsv(fs.readFileSync(path.join(runDir, 'findings-summary.csv'), 'utf8'));

let existing = { accepted: [] };
const outPath = args.out ? path.resolve(process.cwd(), args.out) : path.resolve(process.cwd(), 'security-baseline.json');
if (fs.existsSync(outPath) && !args.overwrite) {
  try { existing = JSON.parse(fs.readFileSync(outPath, 'utf8')); } catch {}
}
const existingFingerprints = new Set((existing.accepted || []).map((e) => e.fingerprint));

const newEntries = [];
for (const f of findings) {
  const fingerprint = fingerprintFinding(f);
  if (existingFingerprints.has(fingerprint)) continue;
  newEntries.push({ fingerprint, category: f.category, title: f.title, url: f.url, reason: args.reason || 'Accepted at baseline snapshot time', expires: args.expires || null });
}

const merged = { accepted: [...(args.overwrite ? [] : existing.accepted || []), ...newEntries] };
fs.writeFileSync(outPath, JSON.stringify(merged, null, 2), 'utf8');
console.log(`Wrote: ${outPath} (${newEntries.length} new exception(s), ${merged.accepted.length} total)`);
