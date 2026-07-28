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
  audit          Full security & attack-surface audit (headers, TLS protocol enumeration,
                 fingerprinting, exposed paths, live GraphQL introspection, port scan, subdomain
                 enum, WHOIS, CVE lookups, PII/payment detection, recon checks, optional
                 authenticated WordPress/Drupal admin audit) + HTML/PDF dashboard
  report         Regenerate the HTML/PDF dashboard from an existing run (e.g. after rebranding)
  tickets        Generate a ticket-ready backlog CSV from a run's findings
  compare        Diff two runs (new/resolved findings, risk grade delta)
  sarif          Convert a run's findings into SARIF for GitHub code scanning
  baseline       Snapshot a run's current findings into a baseline/exceptions file
  batch-audit    Run the full audit across a list of sites, aggregating a summary table
  help           Show this help
  version        Show package version

Examples:
  universal-security-audit audit --site https://www.example.com
  universal-security-audit audit --site https://www.example.com --crawl --max-pages 25
  universal-security-audit audit --site https://www.example.com --intensity aggressive
  universal-security-audit audit --site https://www.example.com --wpscan-key YOUR_KEY
  universal-security-audit audit --site https://www.example.com --skip-exposed-paths --skip-recon
  universal-security-audit audit --site https://www.example.com --login-url https://www.example.com/wp-login.php --username U --password P
  universal-security-audit audit --site https://www.example.com --wp-app-user U --wp-app-password 'xxxx xxxx xxxx xxxx'
  universal-security-audit audit --site https://www.example.com --proxy http://127.0.0.1:8080
  universal-security-audit audit --site https://www.example.com --baseline ./security-baseline.json
  universal-security-audit audit --site https://www.example.com --fail-on high --json > report.json
  universal-security-audit report --run-dir ./reports/<run-id> --brand-config ./branding.json
  universal-security-audit tickets --run-dir ./reports/<run-id>
  universal-security-audit compare --before ./reports/<run-a> --after ./reports/<run-b>
  universal-security-audit sarif --run-dir ./reports/<run-id> --out results.sarif
  universal-security-audit baseline --run-dir ./reports/<run-id> --out ./security-baseline.json
  universal-security-audit batch-audit --sites-file ./sites.txt --intensity light

Key flags (see README for the full list):
  --intensity light|normal|aggressive   Concurrency/delay/probe-size dial
  --wordlist <path>                     Extra paths to probe, one per line
  --skip-port-scan / --skip-subdomain-enum / --skip-whois / --skip-admin-audit
  --auth-config <path> | --login-url/--username/--password   Enables authenticated admin audit
  --wp-app-user / --wp-app-password     WordPress Application Password (preferred over form login)
  --proxy <url>                         Route traffic through Burp/ZAP for manual inspection
  --fail-on <severity> / --min-grade <letter>   CI/CD exit-code gating
  --baseline <path>                     Suppress known-accepted findings from scoring/CI gating
  --json                                Clean JSON on stdout (progress moves to stderr)

Primary outputs (in reports/<site>-<timestamp>/):
  findings-summary.csv          All findings, sorted by severity (includes suppressed column)
  exposed-paths.csv             Every probed admin/config/API path + result
  script-inventory.csv          Detected front-end libraries + versions
  wordpress-components.csv      Detected WP plugins/themes (WordPress sites only)
  vulnerabilities.csv           Matched CVEs/advisories (OSV.dev + WPScan)
  port-scan.csv                 Every scanned port + state + banner
  subdomains.csv                Subdomains found via certificate-transparency logs
  wp-admin-*.csv / drupal-admin-*.csv   Authenticated admin-audit data
  summary.json / full-report.json  Machine-readable run summary / full data dump
  security-dashboard.html/.pdf  Visual risk-graded report
  security-ticket-backlog.csv   Ticket-ready findings (via 'tickets' command)

⚠️  Authorized-use only: this tool actively probes admin/config paths, ports, and
    subdomains on the target. Only run it against sites/infrastructure you own or
    have explicit written permission to test.

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
  case 'sarif':
    run('generate-security-sarif.mjs', rest);
    break;
  case 'baseline':
    run('generate-baseline.mjs', rest);
    break;
  case 'batch-audit':
    run('run-batch-audit.mjs', rest);
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
