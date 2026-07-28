#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

function run(script, args) {
  const scriptPath = path.join(root, 'scripts', script);
  const result = spawnSync(process.execPath, [scriptPath, ...args], { stdio: 'inherit', env: process.env });
  process.exit(result.status ?? 1);
}

function printHelp() {
  console.log(`universal-security-audit

Usage:
  universal-security-audit <command> [options]

Commands:
  audit          Full security & attack-surface audit (headers, fingerprinting, exposed paths,
                 CVE lookups, PII/payment detection, recon checks) + HTML/PDF dashboard
  report         Regenerate the HTML/PDF dashboard from an existing run (e.g. after rebranding)
  tickets        Generate a ticket-ready backlog CSV from a run's findings
  compare        Diff two runs (new/resolved findings, risk grade delta)
  help           Show this help
  version        Show package version

Examples:
  universal-security-audit audit --site https://www.example.com
  universal-security-audit audit --site https://www.example.com --crawl --max-pages 25
  universal-security-audit audit --site https://www.example.com --wpscan-key YOUR_KEY
  universal-security-audit audit --site https://www.example.com --skip-exposed-paths --skip-recon
  universal-security-audit report --run-dir ./reports/<run-id> --brand-config ./branding.json
  universal-security-audit tickets --run-dir ./reports/<run-id>
  universal-security-audit compare --before ./reports/<run-a> --after ./reports/<run-b>

Primary outputs (in reports/<site>-<timestamp>/):
  findings-summary.csv          All findings, sorted by severity
  exposed-paths.csv             Every probed admin/config/API path + result
  script-inventory.csv          Detected front-end libraries + versions
  wordpress-components.csv      Detected WP plugins/themes (WordPress sites only)
  vulnerabilities.csv           Matched CVEs/advisories (OSV.dev + WPScan)
  summary.json                  Machine-readable run summary
  security-dashboard.html/.pdf  Visual risk-graded report
  security-ticket-backlog.csv   Ticket-ready findings (via 'tickets' command)

⚠️  Authorized-use only: this tool actively probes admin/config paths on the target.
    Only run it against sites you own or have explicit written permission to test.

If no command is provided, the CLI defaults to 'audit'.
`);
}

const argv = process.argv.slice(2);
const command = argv[0] && !argv[0].startsWith('--') ? argv[0] : 'audit';
const rest = command === 'audit' ? (argv[0] === 'audit' ? argv.slice(1) : argv) : argv.slice(1);

switch (command) {
  case 'audit':
    run('run-security-audit.mjs', rest);
    break;
  case 'report':
    run('generate-security-report.mjs', rest);
    break;
  case 'tickets':
    run('generate-security-tickets.mjs', rest);
    break;
  case 'compare':
    run('compare-security-runs.mjs', rest);
    break;
  case 'help':
  case '--help':
  case '-h':
    printHelp();
    break;
  case 'version':
  case '--version':
  case '-v':
    console.log('0.1.0');
    break;
  default:
    console.error(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
}
