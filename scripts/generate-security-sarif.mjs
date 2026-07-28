#!/usr/bin/env node
// Converts a run's findings-summary.csv into SARIF 2.1.0 for GitHub code scanning (Security tab).
// Locations use the finding's URL as the artifact URI — the same convention tools like OWASP ZAP's
// SARIF exporter use for web-security findings that aren't tied to a file in the repo.
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
function slugify(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80); }

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SECURITY_SEVERITY = { critical: '9.0', high: '7.0', medium: '5.0', low: '3.0', info: '1.0' };

const args = parseArgs(process.argv);
if (!args['run-dir']) { console.error('Missing --run-dir'); process.exit(1); }
const runDir = path.resolve(process.cwd(), args['run-dir']);
const findings = parseCsv(fs.readFileSync(path.join(runDir, 'findings-summary.csv'), 'utf8')).filter((f) => f.suppressed !== 'true');

const rulesById = new Map();
const results = [];
for (const f of findings) {
  const ruleId = `${slugify(f.category)}--${slugify(f.title)}`;
  if (!rulesById.has(ruleId)) {
    rulesById.set(ruleId, {
      id: ruleId,
      name: f.title,
      shortDescription: { text: f.title },
      fullDescription: { text: f.detail || f.title },
      properties: { 'security-severity': SECURITY_SEVERITY[f.severity] || '1.0', tags: ['security', f.category] },
    });
  }
  const uri = f.url || 'about:blank';
  results.push({
    ruleId,
    level: SARIF_LEVEL[f.severity] || 'note',
    message: { text: f.detail || f.title },
    locations: [{ physicalLocation: { artifactLocation: { uri } } }],
  });
}

const sarif = {
  $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
  version: '2.1.0',
  runs: [{
    tool: {
      driver: {
        name: 'universal-security-audit',
        informationUri: 'https://github.com/pbpyrojust/universal-security-audit',
        version: '0.1.0',
        rules: [...rulesById.values()],
      },
    },
    results,
  }],
};

const outPath = args.out ? path.resolve(process.cwd(), args.out) : path.join(runDir, 'security-findings.sarif');
fs.writeFileSync(outPath, JSON.stringify(sarif, null, 2), 'utf8');
console.log(`Wrote: ${outPath} (${results.length} result(s), ${rulesById.size} rule(s))`);
