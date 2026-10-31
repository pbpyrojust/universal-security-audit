// ── Permission for the active (pentest-style) checks ──
// Passive checks only read what any visitor gets: the pages, response headers, TLS, DNS/WHOIS,
// the files and libraries the pages load, and public vulnerability databases. The active checks
// request what a visitor wouldn't (exposed config/backup paths, admin and login pages, GraphQL
// introspection, open-redirect and HTTP-method probes, WordPress user enumeration, error
// disclosure, subdomain liveness, a TCP port scan) or log in with credentials you supply. Those
// need the site owner's written permission, so they only run once it's confirmed, and the
// confirmation is written into the run's report.
import os from 'node:os';
import readline from 'node:readline/promises';

/** Bump the version whenever the wording changes; each report keeps the exact text confirmed. */
export const AUTHORIZATION_STATEMENT_VERSION = '2026-10-31';
export const AUTHORIZATION_STATEMENT =
  'I own this site, or I have the site owner\'s written permission to security-test it, including requests a normal visitor wouldn\'t make (admin, login and configuration paths, port and subdomain checks, redirect and method probes). I am responsible for having that permission. The tool and its authors accept no liability for how it is used.';

export const ACTIVE_CHECKS = [
  'exposed paths, admin/login pages and GraphQL introspection',
  'subdomain liveness',
  'TCP port scan',
  'recon probes (open redirect, HTTP methods, WordPress user enumeration, error disclosure)',
  'authenticated WordPress/Drupal admin audit',
];

/**
 * Resolves whether the active checks may run. `--authorized` (or `--i-have-permission`) confirms
 * up front, for scripts and CI. Otherwise an interactive terminal is asked to type "yes"; anything
 * else, or no terminal (CI, --json, batch-audit children), means passive checks only.
 */
export async function resolveAuthorization(args, site, { interactive = process.stdin.isTTY && process.stdout.isTTY } = {}) {
  const record = (how) => ({
    confirmed: true,
    how,
    site,
    statement: AUTHORIZATION_STATEMENT,
    statementVersion: AUTHORIZATION_STATEMENT_VERSION,
    at: new Date().toISOString(),
    user: safeUser(),
  });
  if (args['authorized'] || args['i-have-permission']) return record('flag');
  if (!interactive || args['json']) return null;
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  try {
    process.stderr.write(`\n  Active checks on ${site} need the site owner's written permission:\n  "${AUTHORIZATION_STATEMENT}"\n`);
    const answer = (await rl.question('  Type "yes" to confirm and run them, or press Enter for passive checks only: ')).trim().toLowerCase();
    return answer === 'yes' ? record('prompt') : null;
  } finally {
    rl.close();
  }
}

function safeUser() {
  try { return os.userInfo().username; } catch { return null; }
}
