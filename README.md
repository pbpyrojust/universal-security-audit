# Universal Security Audit

Technical security & attack-surface audit CLI. Companion tool to [universal-seo-audit](../universal-seo-audit) and [universal-accessibility-audit](../universal-accessibility-audit) — same crawler/report/ticket/compare conventions, different lens.

Runs a battery of unauthenticated, publicly-visible checks against a website and produces a risk-graded HTML/PDF dashboard, CSV data files, a ticket-ready backlog, and run-over-run comparisons.

## ⚠️ Authorized use only

This tool actively sends requests to well-known admin/login/config paths, DNS-probes common subdomains, TCP-connects to common service ports, and queries third-party vulnerability databases. **Only run it against sites/infrastructure you own or have explicit written permission to test.** Every probe is a single unauthenticated GET/OPTIONS/DNS/TCP-connect to a publicly documented path, record, or port — no auth bypass, brute force, fuzzing, or payload injection is performed, and destructive HTTP verbs (PUT/DELETE) are only *introspected* via OPTIONS, never sent. The one exception is the **authenticated admin audit** (see below), which requires you to supply valid login credentials yourself — it only ever reads screens the logged-in account already has access to. Unauthorized scanning of third-party infrastructure may still violate computer-fraud laws or terms of service even when every individual request is "harmless" on its own.

## What it checks

**Security headers** — A+–F grade covering CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP, `Server`/`X-Powered-By` version disclosure, and cookie `Secure`/`HttpOnly`/`SameSite` flags.

**Platform & infrastructure fingerprinting** — CMS/platform detection (WordPress, Drupal, Joomla, Shopify, Squarespace, Wix, Webflow, Magento, Next.js/SPA); hosting/CDN detection (Cloudflare, Vercel, Netlify, Fastly, AWS S3/CloudFront, GitHub Pages, Pantheon, WP Engine, origin Apache/nginx); DNS records (A/AAAA/MX/NS/TXT); TLS certificate expiry, trust chain, and protocol version (flags TLS 1.0/1.1/SSLv3).

**Exposed path / admin / API discovery** — well-known admin & login pages across platforms (`wp-login.php`, Joomla `/administrator/`, Drupal `/user/login`, cPanel, phpMyAdmin, Adminer, Craft CMS, Umbraco, TYPO3); exposed config/backup files (`.env`, `.git/`, `wp-config.php.bak`, `.htpasswd`, SQL dumps, `phpinfo.php`, `server-status`); exposed APIs (`wp-json`, `wp-json/wp/v2/users`, `xmlrpc.php`, `/graphql`); directory-listing detection.

**Third-party script/library inventory + CVE lookups** — detects common front-end libraries and versions (from filenames, query strings, and CDN path segments), WordPress core/plugin/theme versions (generator meta tag, `readme.html`, plugin `readme.txt` stable tags), Drupal core version (`CHANGELOG.txt`). Cross-references detected versions against:
- **[OSV.dev](https://osv.dev)** (no API key needed) for npm-ecosystem JS libraries (jQuery, Bootstrap, Lodash, Angular, React, Vue, etc.)
- **[WPScan Vulnerability API](https://wpscan.com/api)** (free API key required) for WordPress core, plugins, and themes — findings are filtered against the detected installed version where known

**WHOIS / domain registration** (RDAP) — registrar, creation/expiration/last-changed dates, nameservers, and domain status codes via [RDAP](https://rdap.org) (the modern JSON/HTTP successor to WHOIS — no shelling out to a system `whois` binary). Flags expired or soon-to-expire registrations, since a lapsed domain can be re-registered by an attacker.

**Subdomain enumeration** — passive discovery via [crt.sh](https://crt.sh) certificate-transparency logs (no active DNS brute force), with an optional liveness check (single HEAD request per host, capped by `--intensity`) to see which discovered subdomains currently respond.

**Port scan** — a lightweight Node-native TCP *connect* scan (`node:net`, no nmap dependency) against ~40 common service ports (FTP/SSH/Telnet/SMTP/databases — MySQL/Postgres/MongoDB/Redis/Elasticsearch/Memcached — RDP/VNC/message queues/etc). A connect scan just completes the ordinary TCP handshake and closes, identical to what any client does when it connects; an optional passive banner read (never sends bytes first) is captured when the service volunteers one. Flags any of ~18 "should not be internet-facing" ports (databases, remote admin protocols) found open.

**Recon-phase pentest checks** (all passive or single-request) —
- **Subdomain takeover**: DNS CNAME lookups on the target + common subdomains (`www`, `dev`, `staging`, `api`, `cdn`, etc.), fingerprinted against known dangling-resource response bodies for GitHub Pages, Heroku, AWS S3, Azure, Surge, Bitbucket Pages, Ghost, Pantheon, WP Engine, Fastly, Shopify, Zendesk, Webflow, Netlify
- **HTTP method exposure**: `OPTIONS` request inspects the `Allow` header for risky methods (PUT/DELETE/TRACE/CONNECT) — no risky method is ever actually sent
- **Open redirect**: canary-URL probing of common redirect parameters (`redirect`, `next`, `return`, `dest`, `continue`, etc.), `Location` header inspected but never followed
- **Missing Subresource Integrity (SRI)**: cross-origin `<script>`/`<link>` tags without an `integrity` attribute
- **Exposed source maps**: `.js.map` files that leak original (unminified) source
- **Email spoofing defense**: SPF presence + DMARC record/policy (`_dmarc.<domain>` TXT lookup)
- **WordPress user enumeration**: `?author=1..5` redirect-based username disclosure
- **Insecure login forms**: password fields on plain-HTTP pages or with an `http://` form action
- **Verbose error/debug disclosure**: a nonexistent-path probe checked against PHP/.NET/Java/Python stack-trace signatures
- **JWT cookie weaknesses**: cookies shaped like JWTs are decoded (never verified/forged) and flagged for `alg: none` or a missing `exp` claim

**PII exposure scan** — emails, phone numbers, SSN-like numbers, Luhn-valid credit-card-like numbers, and leaked secrets (AWS access keys, Stripe live secret/publishable keys, Google API keys, Slack tokens, GitHub tokens, PEM private key blocks).

**Payment/donation detection** — Stripe, PayPal, Square, Donorbox, Classy, Network for Good, GiveWP, WooCommerce, Shopify Checkout, Venmo, Braintree, Authorize.Net, Kindful, Bloomerang, Convio/Luminate, plus card-input-without-recognized-processor detection.

**CORS misconfiguration, mixed content, and AI/SEO-crawler exposure** — reflected-Origin + credentials CORS check; `http://` resources on HTTPS pages; what `robots.txt`/`llms.txt`/sitemap reveal publicly (including sensitive-looking `Disallow` paths, which are visible to attackers and AI scrapers even though they aren't blocked).

## Authenticated admin audit (opt-in, WordPress)

If you supply login credentials (see **Authentication** below) and the site is running WordPress, the tool logs in and audits the admin dashboard itself — everything here is a normal page a logged-in user can already see; nothing is written or changed:

- **WordPress core, PHP, and MySQL/MariaDB versions** — from the admin footer and the Site Health debug screen, flags end-of-life PHP versions
- **Every installed plugin** — name, version, active/inactive status, and whether an update is available (including *inactive* plugins, which public-facing scans can't see at all)
- **Every installed theme** — same, parsed from the theme browser's data
- **User accounts + roles** — flags more than 3 Administrator accounts, and flags a literal `admin` username (the first guess in any credential-stuffing attempt)
- **Security plugin presence** — checks active plugins against known security/WAF plugin slugs (Wordfence, Sucuri, iThemes/SolidWP Security, All In One WP Security, Shield Security, WP Cerber, MalCare, Defender, etc.) and flags if none are active

This is the one part of the tool that requires you to hand it real credentials — treat `--auth-config` files as secrets (they're already gitignored) and prefer a dedicated low-privilege-but-sufficient account over your own login where possible.

## Install

```bash
pnpm install
npx playwright install chromium
```

## Usage

```bash
node scripts/run-security-audit.mjs --site https://www.example.com
# or
pnpm security-audit --site https://www.example.com
# or, via the CLI wrapper
node bin/universal-security-audit.mjs audit --site https://www.example.com
```

### Flags

| Flag | Description |
| --- | --- |
| `--site <url>` | **(required)** Target website URL |
| `--max-pages <n>` | Max pages to scan (default 10) |
| `--crawl` | Discover pages by following internal links instead of using the sitemap |
| `--slow` | Conservative mode: longer waits between requests |
| `--respect-robots` | Skip URLs/paths disallowed by robots.txt |
| `--intensity <light\|normal\|aggressive>` | One dial for concurrency/delay/probe-list-size across path probing, port scanning, and subdomain liveness checks (default `normal`) |
| `--wordlist <path>` | Extra file/dir paths to probe (one per line, `#` comments allowed), merged with the built-in curated list |
| `--skip-exposed-paths` | Skip the admin/login/config/API path-probing phase |
| `--skip-cve` | Skip live OSV.dev/WPScan CVE lookups |
| `--skip-recon` | Skip the recon-phase checks (subdomain takeover, open redirect, SRI, source maps, SPF/DMARC, user enum, verbose errors) |
| `--skip-port-scan` | Skip the TCP port scan |
| `--skip-subdomain-enum` | Skip crt.sh subdomain enumeration |
| `--skip-whois` | Skip the WHOIS/RDAP domain-registration lookup |
| `--skip-admin-audit` | Skip the authenticated admin audit even if credentials are supplied |
| `--wpscan-key <key>` | WPScan Vulnerability API token (or set `WPSCAN_API_KEY` env var) |
| `--brand-config <path>` | JSON file to white-label the HTML/PDF report (see below) |
| `--proxy <url>` | Route all traffic (fetch + browser) through an upstream proxy, e.g. Burp Suite / OWASP ZAP, for manual inspection/replay |
| `--fail-on <severity>` | Exit code 1 if any finding at or above this severity exists (`critical`/`high`/`medium`/`low`) — for CI gating |
| `--min-grade <letter>` | Exit code 1 if the overall risk grade is below this letter (e.g. `--min-grade B`) — for CI gating |
| `--json` | Print the full findings/report as JSON to stdout (all progress output moves to stderr, so stdout stays clean for piping to `jq` etc.) — `full-report.json` is always written to the run directory regardless of this flag |

### Authentication

For the authenticated admin audit (and for scanning staging/password-protected sites in general):

| Flag | Description |
| --- | --- |
| `--auth-config <path>` | JSON file with any of the fields below (see `auth-config.example.json`) |
| `--http-username` / `--http-password` | HTTP Basic Auth credentials (or `USA_HTTP_USERNAME`/`USA_HTTP_PASSWORD` env vars) |
| `--login-url <url>` | Form-based login page (e.g. `https://example.com/wp-login.php`) — supplying this + `--username` enables the authenticated admin audit |
| `--username` / `--password` | Form login credentials (or `USA_LOGIN_USERNAME`/`USA_LOGIN_PASSWORD` env vars) |
| `--username-selector` / `--password-selector` / `--submit-selector` | CSS selectors for the login form fields (default to WordPress's `wp-login.php` field names) |
| `--ready-selector` | A selector to wait for post-login as a "login succeeded" signal |
| `--post-login-wait-ms` | Fallback wait time after submitting the login form (default 2000ms) |

```bash
node scripts/run-security-audit.mjs --site https://www.example.com \
  --login-url https://www.example.com/wp-login.php \
  --username your-admin-user --password your-admin-password
```

### WordPress CVE lookups

WordPress core/plugin/theme vulnerability matching uses the [WPScan Vulnerability Database API](https://wpscan.com/api). Register for a free API key (25 requests/day) at wpscan.com, then either:

```bash
export WPSCAN_API_KEY=your-key-here
node scripts/run-security-audit.mjs --site https://www.example.com
```

or pass `--wpscan-key your-key-here`. Without a key, core/plugin/theme versions are still detected and reported — just without live CVE matching.

## Output

Each run writes to `reports/<site>-<timestamp>/`:

| File | Contents |
| --- | --- |
| `security-dashboard.html` / `.pdf` | Visual risk-graded report |
| `findings-summary.csv` | All findings, sorted by severity |
| `exposed-paths.csv` | Every probed admin/config/API path and its result |
| `script-inventory.csv` | Detected front-end libraries + versions |
| `wordpress-components.csv` | Detected WP plugins/themes + versions, from public-facing detection (WordPress sites only) |
| `vulnerabilities.csv` | Matched CVEs/advisories from OSV.dev + WPScan |
| `port-scan.csv` | Every scanned port, its state (open/closed/filtered), and any banner captured |
| `subdomains.csv` | Subdomains discovered via certificate-transparency logs (when any are found) |
| `wp-admin-plugins.csv` / `wp-admin-themes.csv` / `wp-admin-users.csv` | Authenticated admin-audit data (only written when login credentials were supplied and the audit succeeded) |
| `summary.json` | Machine-readable summary: risk grade, platform, hosting, DNS, TLS, WHOIS, subdomains, open ports, admin-audit data |
| `full-report.json` | Everything in `summary.json` plus every finding, all matched CVEs, all exposed-path results, and the full library inventory — the same document `--json` prints to stdout |

## Reports, tickets, and comparisons

Same workflow shape as `universal-seo-audit` / `universal-accessibility-audit`: the live audit produces raw data, and three standalone scripts turn it into deliverables — usable independently of a live scan, against any existing `reports/<run>` directory.

### Regenerate / re-brand the dashboard

```bash
node scripts/generate-security-report.mjs --run-dir reports/<run-folder> --brand-config ./branding.json
```

Rebuilds `security-dashboard.html`/`.pdf` from a run's `summary.json` + CSVs without re-scanning the site. Useful for white-labeling a past run or after a template change.

`branding.json` (see `branding.example.json`):

```json
{
  "companyName": "JustWhat.net",
  "logo": "./assets/logo.png",
  "primaryColor": "#ef4444",
  "secondaryColor": "#0f172a",
  "accentColor": "#22c55e",
  "reportTitle": "Security & Attack Surface Audit",
  "author": "Justin Adams",
  "footerText": "Confidential — Prepared by JustWhat.net"
}
```

### Ticket-ready backlog

```bash
node scripts/generate-security-tickets.mjs --run-dir reports/<run-folder>
```

Writes `security-ticket-backlog.csv`: one ticket per site-wide issue (headers, TLS, CVEs, exposed paths, recon findings — deduped across pages) plus one ticket per page-level finding (PII, mixed content, missing SRI, insecure login forms, JWT issues), each with a priority (`P0`–`P4` from severity), description, and label set — ready to import into GitHub Issues, Jira, Linear, etc.

### Compare two runs over time

```bash
node scripts/compare-security-runs.mjs --before reports/run-a --after reports/run-b
```

Writes `security-compare-summary.csv` (severity counts before/after/delta), `security-compare-new-findings.csv`, `security-compare-resolved-findings.csv`, and a human-readable `security-compare-summary.md` — including the risk-grade delta. Use this after remediation work to confirm fixes landed and nothing regressed.

### CLI wrapper

All of the above are also reachable through the packaged CLI:

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com
node bin/universal-security-audit.mjs report --run-dir reports/<run-folder> --brand-config ./branding.json
node bin/universal-security-audit.mjs tickets --run-dir reports/<run-folder>
node bin/universal-security-audit.mjs compare --before reports/run-a --after reports/run-b
node bin/universal-security-audit.mjs help
```

## Risk grading

Every finding is tagged `critical` / `high` / `medium` / `low` / `info`. The overall grade (A+–F) is a weighted deduction from 100 based on finding severity (critical −25, high −12, medium −5, low −2, info −0) — the header-grading module uses the same deduction methodology on its own 0–100 scale, loosely modeled on securityheaders.com / Mozilla Observatory.

## Roadmap / not built yet

- `--crawl` is single-pass BFS link-following; no per-domain crawl-delay tuning yet
- No Drupal-specific CVE feed (SA-CORE) — Drupal core version is detected and reported, but not cross-referenced against known CVEs yet
- No favicon-hash-based CMS fingerprint boost
- Authenticated admin audit is WordPress-only for now (Drupal/other CMS admin scanning not yet built)
- Port scan is TCP-connect only (no UDP, no service-version fingerprinting beyond a passive banner read)
