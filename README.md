# Universal Security Audit

Technical security & attack-surface audit CLI. Companion tool to [universal-seo-audit](../universal-seo-audit) and [universal-accessibility-audit](../universal-accessibility-audit) — same crawler/report/ticket/compare conventions, different lens.

Runs a battery of unauthenticated, publicly-visible checks against a website and produces a risk-graded HTML/PDF dashboard, CSV data files, a ticket-ready backlog, and run-over-run comparisons.

## What's new in 0.3.0

- **Pentest checks need confirmed permission.** The active checks (exposed paths and admin/login pages, GraphQL introspection, subdomain liveness, the port scan, open-redirect/HTTP-method/user-enumeration/error-disclosure probes, and the authenticated admin audit) only run when you confirm you own the site or have the owner's written permission: `--authorized`, or typing "yes" at the prompt. Without it a run is passive only. The confirmation (exact statement, time, user, how) is saved in `summary.json` and `full-report.json`. **Scripts and CI that relied on the active checks need `--authorized` added.**
- **Open redirect:** only a redirect whose destination is the test host counts. Sites that redirect www → apex (or http → https) keep the query string, which made every redirect parameter a false positive.
- **WPScan:** a refused key (WPScan answers 403 for a missing or invalid token) now stops the lookups after the first one with one message.
- **Wordfence Intelligence** as a second source of WordPress core/plugin/theme vulnerabilities, with your own free key (`--wordfence-key` or `WORDFENCE_API_KEY`). Only for sites detected as WordPress. The feed is downloaded at most once a day and kept as a compact index in `~/.cache/universal-security-audit/`; components WPScan already reported aren't repeated. See [WordPress CVE lookups](#wordpress-cve-lookups).

## What's new in 0.2.0

- **security.txt (RFC 9116) validation:** finds it at `/.well-known/security.txt` (or the legacy `/security.txt`) and checks the required Contact and Expires fields, an expiry date that hasn't passed (and isn't more than a year out), HTTPS, `text/plain`, Canonical and Policy; reports PGP signing. A missing or expired file is a finding.
- **WPScan free tier:** when the daily limit (25 requests) is hit, the remaining WordPress CVE lookups are skipped with one clear message instead of an error per plugin.
- Playwright 1.64, undici 8.12 and current dependencies.

## Part of Vinny

This scanner is the free, open-source engine behind the [security checks in Vinny](https://vinny.justwhat.net/features/#security). Everything here stays free. [Vinny](https://vinny.justwhat.net) runs the same header grading on a schedule for any website, alongside [accessibility](https://vinny.justwhat.net/features/#accessibility), [SEO and rank tracking](https://vinny.justwhat.net/features/#seo), with history, alerts and fix tickets ([free for one site](https://vinny.justwhat.net/pricing/)). For WordPress, the [Universal Security Audit plugin](https://wordpress.justwhat.net/#plugins-heading) is coming soon.

## ⚠️ Authorized use only: pentest checks need written permission

**Only run this tool against sites and infrastructure you own, or that you have the owner's explicit written permission to test.** Some of what it does is the recon phase of a penetration test, and in many places requests like these count as security testing that needs permission, even when every request is harmless on its own. Unauthorized scanning can break computer-misuse laws (such as the US CFAA or the UK Computer Misuse Act) and hosting providers' terms. Permission from a site's owner doesn't cover the hosting company's own servers: many hosts forbid port scans of their network, so add `--skip-port-scan` unless the host allows it.

The checks come in two kinds:

- **Passive (always on):** what any visitor gets. The pages, response headers and cookies, TLS, DNS and WHOIS, security.txt, the scripts and libraries the pages load, and public vulnerability databases (OSV.dev, WPScan).
- **Active (pentest-style, need confirmed permission):** exposed config/backup/admin/login/API paths and GraphQL introspection, subdomain liveness, a TCP port scan, open-redirect, HTTP-method, WordPress user-enumeration and error-disclosure probes, and the authenticated WordPress/Drupal admin audit.

The active checks only run after you confirm: pass `--authorized` (for scripts and CI), or type "yes" when an interactive run asks. Without that, a run is passive only and says what it skipped. The confirmation is written into the run's `summary.json` and `full-report.json` (`authorization`: the exact statement and its version, the time, your OS user name and how it was given), so each report shows what was agreed.

Even the active checks stay gentle: every probe is a single GET, OPTIONS, DNS lookup or TCP connect to a publicly documented path, record or port. No auth bypass, brute force, fuzzing or payload injection; destructive HTTP verbs (PUT/DELETE) are only *introspected* via OPTIONS, never sent. The authenticated admin audit only uses credentials you supply and only reads screens that account can already see.

**No warranty, no liability.** This software is provided "as is" under the MIT License (see `LICENSE`): the authors aren't liable for any claim or damage arising from its use. You are solely responsible for having permission for every site you test and for how you use the results.

## What it checks

**Security headers** — A+–F grade covering CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP, `Server`/`X-Powered-By` version disclosure, and cookie `Secure`/`HttpOnly`/`SameSite` flags.

**Platform & infrastructure fingerprinting** — CMS/platform detection (WordPress, Drupal, Joomla, Shopify, Squarespace, Wix, Webflow, Magento, Ruby on Rails, Next.js/SPA); hosting/CDN detection (Cloudflare, Vercel, Netlify, Fastly, AWS S3/CloudFront, GitHub Pages, Pantheon, WP Engine, origin Apache/nginx); DNS records (A/AAAA/MX/NS/TXT); TLS certificate expiry and trust chain. Rails is detected via its CSRF meta tags (`csrf-param`/`csrf-token`), `authenticity_token` form fields, the `X-Runtime` header, or its default `_appname_session` cookie naming convention.

**Multi-platform / hybrid-architecture detection** — platform signals and backend headers (`Server`/`X-Powered-By`) are compared *across every scanned page*, not just the homepage. A different high-confidence platform (or a different backend header) showing up on a different page is reported as a likely hybrid architecture (e.g. a WordPress marketing site with a separately-built donation/fundraising app) — each stack has its own patching surface and CVE exposure. This only works as well as your page coverage: use `--crawl` with a reasonable `--max-pages` for sites you suspect might be hybrid, since a single-page scan can only ever see whichever platform served that one page.

**Multi-server / reverse-proxy detection** — three complementary signals, all built from data the tool is already collecting or a handful of extra plain GETs to the homepage:
- **Reverse proxy indicators**: a `Via` header, or seeing both a CDN/edge signal (Cloudflare, Fastly, etc.) and an origin-server signal (nginx/Apache) in the same response
- **DNS load-balancing hint**: more than one A record with no recognized CDN in front (CDNs also return multiple IPs, but those are edge nodes, not your own servers — already excluded)
- **Response-header consistency**: several repeated requests to the homepage compared for `Server`/`X-Powered-By`/`Via`/`X-Served-By` differences — inconsistent answers to the same URL over time is a solid signal of multiple backend instances behind a load balancer that may not be equally patched/configured

**TLS protocol enumeration** — actually handshakes with the server pinned to each of TLS 1.0/1.1/1.2/1.3 (rather than only reporting whatever one default connection negotiated) and flags legacy protocols that are still accepted. Note: forcing specific *weak cipher suites* (RC4/3DES/NULL/export-grade) isn't included — modern Node's bundled OpenSSL has those compiled out entirely, so we cannot reliably ask a server that question from this client; claiming to test for them would risk a false "not vulnerable" reading.

**Exposed path / admin / API discovery** — well-known admin & login pages across platforms (`wp-login.php`, Joomla `/administrator/`, Drupal `/user/login`, cPanel, phpMyAdmin, Adminer, Craft CMS, Umbraco, TYPO3); exposed config/backup files (`.env`, `.git/`, `wp-config.php.bak`, `.htpasswd`, SQL dumps, `phpinfo.php`, `server-status`); exposed APIs (`wp-json`, `wp-json/wp/v2/users`, `xmlrpc.php`, `/graphql`); directory-listing detection. When a `/graphql` endpoint is found, the tool sends a real (read-only, standard) introspection query — if introspection is enabled, the response hands over the entire schema, so exposed type/mutation names (especially sensitive-sounding ones like `deleteUser`) are reported directly.

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

**CORS misconfiguration, mixed content, and AI/SEO-crawler exposure** — reflected-Origin + credentials CORS check; `http://` resources on HTTPS pages; what `robots.txt`/`llms.txt`/sitemap reveal publicly (including sensitive-looking `Disallow` paths, which are visible to attackers and AI scrapers even though they aren't blocked). Sitemap discovery reads any `Sitemap:` directive(s) in `robots.txt` first (taking priority over guessing `sitemap_index.xml`/`wp-sitemap.xml`/`sitemap.xml`), and cross-checks the two: it flags when a working sitemap exists but isn't declared in `robots.txt` (crawlers that only read `robots.txt` for sitemap discovery would miss it) and when `robots.txt` declares a sitemap URL that doesn't actually resolve.

## Authenticated admin audit (opt-in, WordPress + Drupal)

If you supply credentials (see **Authentication** below) and the site is running WordPress or Drupal, the tool logs in and audits the admin dashboard itself — everything here is a normal screen the logged-in account already has access to; nothing is written or changed.

### WordPress

Two ways to authenticate, checked in this order:

1. **Application Passwords (preferred)** — `--wp-app-user`/`--wp-app-password`. Uses the official REST API (`/wp-json/wp/v2/*`) over HTTP Basic Auth — no Playwright login, no HTML scraping, stable across admin-theme/core UI changes. Create one under **Users → Profile → Application Passwords** in wp-admin. Plugin/theme "outdated" status is cross-referenced against the official [wordpress.org Plugin/Theme Directory API](https://api.wordpress.org) rather than scraped update-nag text.
2. **Form login (fallback)** — `--login-url`/`--username`/`--password`. Logs into `wp-login.php` with Playwright and scrapes `wp-admin` screens directly (plugins, themes, Site Health, users). Used automatically when no Application Password is supplied.

Either way, it reports:
- **WordPress core, PHP, and MySQL/MariaDB versions** (form-login method only — Application Passwords don't expose these via REST) — flags end-of-life PHP versions
- **Every installed plugin/theme** — name, version, active/inactive status, and outdated status (including *inactive* ones, which public-facing scans can't see at all)
- **User accounts + roles** — flags more than 3 Administrator accounts, and a literal `admin` username (the first guess in any credential-stuffing attempt)
- **Security plugin presence** — checks active plugins against known security/WAF plugin slugs (Wordfence, Sucuri, iThemes/SolidWP Security, All In One WP Security, Shield Security, WP Cerber, MalCare, Defender, etc.) and flags if none are active

### Drupal

Form login only (`--login-url`/`--username`/`--password` against `/user/login`), then:
- **Drupal core, PHP, and database versions** from `/admin/reports/status` (parsed from visible text rather than theme-specific CSS classes, since Drupal admin themes vary more than WordPress's) — flags end-of-life Drupal major versions and PHP versions, and counts error/warning-level status-report items
- **Installed modules** — name, version, enabled/disabled status, from `/admin/modules`
- **User accounts + roles** — from `/admin/people`, same Administrator-count and `admin`-username checks as WordPress

This is the one part of the tool that requires you to hand it real credentials — treat `--auth-config` files (and Application Passwords) as secrets (they're already gitignored) and prefer a dedicated low-privilege-but-sufficient account over your own login where possible.

## Install

From npm (`@pbpyrojust/universal-security-audit`):

```bash
npm install -g @pbpyrojust/universal-security-audit
npx playwright install chromium
universal-security-audit --site https://www.example.com
```

Or without installing: `npm exec --package @pbpyrojust/universal-security-audit -- universal-security-audit --site https://www.example.com`.

From a clone of this repository:

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
| `--authorized` | Confirm you own the site or have the owner's written permission, so the active (pentest-style) checks run; recorded in the report. Without it, an interactive run asks, and a non-interactive one (CI, `--json`, batch) is passive only. Alias `--i-have-permission` |
| `--max-pages <n>` | Max pages to scan. Omit it and there's no limit — sitemap discovery pulls every URL it finds, and `--crawl` follows links until it exhausts the site; pass a number to cap either one on large sites |
| `--crawl` | Discover pages by following internal links instead of using the sitemap |
| `--max-per-url-pattern <n>` | Crawl-trap guard (default 3): caps how many pages matching the same URL "shape" get crawled — path segments that look like IDs/hashes/years (`/participants/mypage/1174017/2026`) are collapsed to a placeholder (`/participants/mypage/:id/:id`) for this comparison, so a site with thousands of per-record pages (fundraiser pages, product pages, forum threads) doesn't turn an uncapped `--crawl` into tens of thousands of near-duplicate requests |
| `--max-depth <n>` | How many link "hops" from the homepage `--crawl` follows: `0` = homepage only, `1` = homepage + whatever it links to, `2` = plus one more layer, etc. Omit for no limit. Combine with a small `--max-pages` for a quick "top-level pages only" pass |
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
| `--wordfence-key <key>` | Your own Wordfence Intelligence API key (or set `WORDFENCE_API_KEY`): free, commercial use allowed with attribution. WordPress sites only; see [WordPress CVE lookups](#wordpress-cve-lookups) |
| `--wpscan-key <key>` | Your own WPScan Vulnerability API token (or set `WPSCAN_API_KEY` env var) — free tier is 25 requests/day; see [WordPress CVE lookups](#wordpress-cve-lookups) |
| `--brand-config <path>` | JSON file to white-label the HTML/PDF report (see below) |
| `--proxy <url>` | Route all traffic (fetch + browser) through an upstream proxy, e.g. Burp Suite / OWASP ZAP, for manual inspection/replay |
| `--fail-on <severity>` | Exit code 1 if any *active* (non-suppressed) finding at or above this severity exists (`critical`/`high`/`medium`/`low`) — for CI gating |
| `--min-grade <letter>` | Exit code 1 if the overall risk grade is below this letter (e.g. `--min-grade B`) — for CI gating |
| `--baseline <path>` | JSON file of known-accepted findings (by fingerprint) to suppress from scoring/CI gating while keeping them visible in the report — see **Baseline / exceptions** below |
| `--json` | Print the full findings/report as JSON to stdout (all progress output moves to stderr, so stdout stays clean for piping to `jq` etc.) — `full-report.json` is always written to the run directory regardless of this flag |

### Authentication

For the authenticated admin audit (and for scanning staging/password-protected sites in general):

| Flag | Description |
| --- | --- |
| `--auth-config <path>` | JSON file with any of the fields below (see `auth-config.example.json`) |
| `--http-username` / `--http-password` | HTTP Basic Auth credentials (or `USA_HTTP_USERNAME`/`USA_HTTP_PASSWORD` env vars) |
| `--wp-app-user` / `--wp-app-password` | WordPress Application Password (or `USA_WP_APP_USER`/`USA_WP_APP_PASSWORD` env vars) — **preferred** for the WP admin audit; no Playwright login needed |
| `--login-url <url>` | Form-based login page (e.g. `https://example.com/wp-login.php` or `/user/login` for Drupal) — supplying this + `--username` enables the authenticated admin audit when no Application Password is given |
| `--username` / `--password` | Form login credentials (or `USA_LOGIN_USERNAME`/`USA_LOGIN_PASSWORD` env vars) |
| `--username-selector` / `--password-selector` / `--submit-selector` | CSS selectors for the login form fields (default to WordPress's `wp-login.php` field names) |
| `--ready-selector` | A selector to wait for post-login as a "login succeeded" signal |
| `--post-login-wait-ms` | Fallback wait time after submitting the login form (default 2000ms) |

```bash
# WordPress via Application Password (preferred):
node scripts/run-security-audit.mjs --site https://www.example.com \
  --wp-app-user your-admin-user --wp-app-password "xxxx xxxx xxxx xxxx xxxx xxxx"

# WordPress or Drupal via form login (fallback):
node scripts/run-security-audit.mjs --site https://www.example.com \
  --login-url https://www.example.com/wp-login.php \
  --username your-admin-user --password your-admin-password
```

### WordPress CVE lookups

WordPress core/plugin/theme vulnerability matching only runs for sites detected as WordPress, and only with a key you supply. Two sources, use either or both:

- **[Wordfence Intelligence](https://www.wordfence.com/threat-intel/)** (`WORDFENCE_API_KEY` or `--wordfence-key`): free for commercial and personal use with attribution; create a key at wordfence.com under Account → Integrations. The full feed (~160 MB) is downloaded at most once every 24 hours and kept as a compact index (~18 MB) in `~/.cache/universal-security-audit/wordfence-index.json` (or `$XDG_CACHE_HOME`); the key's download limit is small, so if a refresh is refused the cached copy is used. Findings credit Wordfence and Defiant Inc. as its license requires.
- **WPScan**: uses the [WPScan Vulnerability Database API](https://wpscan.com/api), which requires an API key — there's no shared/bundled key in this repo, so each user registers their own for free at wpscan.com. Set it either way:

```bash
export WPSCAN_API_KEY=your-key-here
node scripts/run-security-audit.mjs --site https://www.example.com
```

or pass it per-run with `--wpscan-key your-key-here` (this takes precedence over the env var). Without a key, core/plugin/theme versions are still detected and reported — just without live CVE matching.

The free WPScan tier is capped at **25 requests/day**. If a scan hits that cap mid-run (checking WordPress core plus every detected plugin/theme can use up the quota quickly), the tool detects the `429` response, prints a one-time warning to the console telling you the daily limit was hit, and skips the remaining WPScan lookups for that run rather than continuing to burn failed requests — everything else in the scan (headers, exposed paths, PII/payment detection, non-WPScan CVE sources, etc.) still completes normally. The quota resets daily; see [wpscan.com/api](https://wpscan.com/api) for paid tiers with a higher limit.

## Output

Each run writes to `reports/<site>-<timestamp>/`:

| File | Contents |
| --- | --- |
| `security-dashboard.html` / `.pdf` | Visual risk-graded report |
| `findings-summary.csv` | All findings, sorted by severity — includes `suppressed`/`suppressedReason` columns when `--baseline` is used |
| `exposed-paths.csv` | Every probed admin/config/API path and its result |
| `script-inventory.csv` | Detected front-end libraries + versions |
| `wordpress-components.csv` | Detected WP plugins/themes + versions, from public-facing detection (WordPress sites only) |
| `vulnerabilities.csv` | Matched CVEs/advisories from OSV.dev + WPScan |
| `port-scan.csv` | Every scanned port, its state (open/closed/filtered), and any banner captured |
| `subdomains.csv` | Subdomains discovered via certificate-transparency logs (when any are found) |
| `wp-admin-plugins.csv` / `wp-admin-themes.csv` / `wp-admin-users.csv` | Authenticated WordPress admin-audit data (only written when credentials were supplied and the audit succeeded) |
| `drupal-admin-modules.csv` / `drupal-admin-users.csv` | Authenticated Drupal admin-audit data |
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

Writes `security-compare-summary.csv` (severity counts before/after/delta), `security-compare-new-findings.csv`, `security-compare-resolved-findings.csv`, and a human-readable `security-compare-summary.md` — including the risk-grade delta. Add `--out-dir <path>` to write these somewhere other than the "after" run's own directory (the default). Use this after remediation work to confirm fixes landed and nothing regressed.

### SARIF export (GitHub code scanning)

```bash
node scripts/generate-security-sarif.mjs --run-dir reports/<run-folder> --out results.sarif
```

Converts `findings-summary.csv` into a valid SARIF 2.1.0 document — severity maps to SARIF `level` (critical/high → `error`, medium → `warning`, low/info → `note`) plus a `security-severity` score GitHub uses for its Security tab display. Locations use each finding's URL as the artifact URI (the same convention OWASP ZAP's SARIF exporter uses for web findings that aren't tied to a repo file). Wire it into a workflow with `github/codeql-action/upload-sarif`.

### Baseline / exceptions

Known-accepted findings can be suppressed from risk scoring and `--fail-on`/`--min-grade` CI gating on future runs, without hiding them from the report:

```bash
# Snapshot everything from the current run as accepted (edit the output afterward to add real reasons/expiry):
node scripts/generate-baseline.mjs --run-dir reports/<run-folder> --out ./security-baseline.json --reason "Accepted 2026-Q3, ticket JIRA-123"

# Use it on future runs:
node scripts/run-security-audit.mjs --site https://www.example.com --baseline ./security-baseline.json
```

Suppression is keyed on a stable fingerprint of `category + title + url`, so a finding stays suppressed as long as it's the same issue at the same location. Suppressed findings still appear in `findings-summary.csv` and the dashboard (dimmed, with the acceptance reason), they just don't count toward the risk grade or trip `--fail-on`/`--min-grade`. Add an `"expires"` date (ISO format) to any baseline entry to make the exception temporary — after that date it stops applying automatically. `generate-baseline.mjs` flags: `--out <path>` (default `./security-baseline.json`), `--reason <text>`, `--expires <ISO date>`, `--overwrite` (replace the file instead of merging new exceptions into it).

### Multi-site batch scanning

```bash
node scripts/run-batch-audit.mjs --sites-file ./sites.txt --intensity light --skip-cve --concurrency 2 --out-dir ./reports
```

`sites.txt` is one URL per line (`#` comments allowed). Runs the full audit against each site (`--concurrency N`, default 1/sequential — keep this low, each run launches its own browser), forwarding every other flag through to each individual audit. Every site still gets its normal `reports/<site>-<timestamp>/` output, plus an aggregated `batch-summary-<id>.csv`/`.md` (`--out-dir` controls where, default `./reports`) with one row per site (grade, score, severity counts) sorted worst-first — useful for agencies auditing a portfolio of client sites in one pass.

### CLI wrapper

All of the above are also reachable through the packaged CLI:

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com
node bin/universal-security-audit.mjs report --run-dir reports/<run-folder> --brand-config ./branding.json
node bin/universal-security-audit.mjs tickets --run-dir reports/<run-folder>
node bin/universal-security-audit.mjs compare --before reports/run-a --after reports/run-b
node bin/universal-security-audit.mjs sarif --run-dir reports/<run-folder> --out results.sarif
node bin/universal-security-audit.mjs baseline --run-dir reports/<run-folder> --out ./security-baseline.json
node bin/universal-security-audit.mjs batch-audit --sites-file ./sites.txt
node bin/universal-security-audit.mjs help
```

## Example workflows by site type / use case

### Small stakeholder-facing overview (skip deep/individual-record pages)

For sites with lots of per-record pages (fundraiser/participant pages, product listings, forum threads, etc.) where you just want a quick, presentable snapshot rather than exhaustive coverage:

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com \
  --crawl --max-depth 2 --max-pages 25 --intensity light --respect-robots
```

`--max-depth 2` keeps the crawl to the homepage, its direct nav links, and one layer of their children — the pages that actually represent the site's structure — without falling into individual per-record pages several links deep. `--max-pages 25` is a backstop in case even that top layer is large. Good enough to hand stakeholders a representative grade and findings list without a multi-hour run.

### Quick first-pass on a live WordPress site

Fast and unauthenticated, but the active checks still need the client's written permission first (`--authorized` records that you have it):

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com --intensity light --authorized
```

### Full authenticated WordPress security review

Agency-style deep audit: create an Application Password in the client's wp-admin first (Users → Profile → Application Passwords), get a free [WPScan API key](https://wpscan.com/api), then:

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com \
  --wp-app-user admin --wp-app-password "xxxx xxxx xxxx xxxx xxxx xxxx" \
  --wpscan-key YOUR_WPSCAN_KEY --crawl --max-pages 50 --authorized
node bin/universal-security-audit.mjs tickets --run-dir ./reports/<run-id>
```

Gives you plugin/theme CVEs, outdated inactive plugins nobody remembers installing, missing security plugins, and a ticket-ready backlog in one pass.

### Drupal site

Same shape, form-login only (no Application Passwords in Drupal core):

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com \
  --login-url https://www.example.com/user/login --username admin --password your-password --authorized
```

### E-commerce / donation site

Payment-processor and PCI-scope questions matter most here; a full run already covers this, but it's worth calling out what to look at in the output — the `payment` category in `findings-summary.csv` and the "Payment/donation" card on the dashboard:

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com
```

Look for: a card-input form without a recognized tokenizing processor (Stripe/Square/Braintree/Authorize.Net) flagged `high`, missing HSTS/CSP on checkout pages, and mixed-content resources on any page that touches payment.

### Staging / password-protected site (HTTP Basic Auth)

```bash
node bin/universal-security-audit.mjs audit --site https://staging.example.com \
  --http-username staging-user --http-password staging-pass --respect-robots
```

### CI/CD gate on every deploy (GitHub Actions)

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com \
  --intensity light --skip-port-scan --skip-subdomain-enum --authorized \
  --baseline ./security-baseline.json --fail-on high --json > report.json
node bin/universal-security-audit.mjs sarif --run-dir "$(ls -td reports/*/ | head -1)" --out results.sarif
```

Then upload `results.sarif` with `github/codeql-action/upload-sarif` so findings show up in the repo's Security tab. `--fail-on high` fails the build on anything high/critical that isn't already in the baseline; port scan/subdomain enum are skipped here since they're slower and less relevant to "did this deploy regress anything."

### Agency portfolio — many client sites on a schedule

```bash
node bin/universal-security-audit.mjs batch-audit --sites-file ./client-sites.txt \
  --intensity light --skip-cve --concurrency 2 --authorized
```

Pair with a cron/scheduled job and diff each site's `summary.json` week over week (or use `compare` against the prior run per site) to catch regressions before a client notices.

### Custom app / SPA / non-CMS site (Next.js, headless, etc.)

Platform fingerprinting won't find a CMS to fingerprint here, so CVE/plugin-version checks won't have much to do — the value comes from headers, TLS, CORS, exposed paths, port scan, and PII/secret scanning instead:

```bash
node bin/universal-security-audit.mjs audit --site https://app.example.com --skip-cve
```

### Confirm remediation actually worked

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com --intensity light   # after fixes
node bin/universal-security-audit.mjs compare --before ./reports/<before-run> --after ./reports/<after-run>
```

Check `security-compare-summary.md` for the risk-grade delta and confirm the specific findings you fixed show up under "Resolved findings," not "New findings" (which would mean something regressed elsewhere).

### One-time deep pentest-style engagement

Maximum coverage, routed through Burp Suite so a human can inspect/replay anything interesting:

```bash
node bin/universal-security-audit.mjs audit --site https://www.example.com \
  --intensity aggressive --crawl --max-pages 100 \
  --wordlist ./my-wordlist.txt --proxy http://127.0.0.1:8080 \
  --wp-app-user admin --wp-app-password "xxxx xxxx xxxx xxxx xxxx xxxx" --wpscan-key YOUR_KEY --authorized
```

## Risk grading

Every finding is tagged `critical` / `high` / `medium` / `low` / `info`. The overall grade (A+–F) is a weighted deduction from 100 based on finding severity (critical −25, high −12, medium −5, low −2, info −0) — the header-grading module uses the same deduction methodology on its own 0–100 scale, loosely modeled on securityheaders.com / Mozilla Observatory.

## Roadmap / not built yet

- `--crawl` is single-pass BFS link-following; no per-domain crawl-delay tuning yet
- No Drupal-specific CVE feed (SA-CORE) — Drupal core version is detected and reported, but not cross-referenced against known CVEs yet
- No favicon-hash-based CMS fingerprint boost
- Port scan is TCP-connect only (no UDP, no service-version fingerprinting beyond a passive banner read); weak-cipher-suite forcing isn't included (see the TLS section above for why)
- No login rate-limit/lockout detection or password-reset account enumeration — both are real pentest signals, but risk locking out real accounts or sending real emails, so they'd need explicit opt-in and heavy guardrails if ever added
