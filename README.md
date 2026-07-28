# Universal Security Audit

Technical security & attack-surface audit CLI. Companion tool to [universal-seo-audit](../universal-seo-audit) and [universal-accessibility-audit](../universal-accessibility-audit) — same crawler/report conventions, different lens.

Runs a battery of unauthenticated, publicly-visible checks against a website and produces a risk-graded HTML/PDF dashboard plus CSV data files:

- **Security header grading** (A+–F) — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP, cookie flags
- **CMS/platform fingerprinting** — WordPress, Drupal, Joomla, Shopify, Squarespace, Wix, Webflow, Magento, Next.js/SPA
- **Hosting/CDN + infrastructure** — Cloudflare/Vercel/Netlify/Fastly/CloudFront/etc. detection, DNS records (A/AAAA/MX/NS/TXT), TLS certificate & protocol check
- **Exposed path / admin / API discovery** — well-known admin & login pages, exposed config/backup files (`.env`, `.git/`, `wp-config.php.bak`, etc.), exposed APIs (`wp-json`, `xmlrpc.php`, `/graphql`), directory-listing detection
- **Third-party script/library inventory** — detects common front-end libraries + versions, WordPress core/plugin/theme versions, Drupal core version
- **Live CVE lookups** — [OSV.dev](https://osv.dev) for npm-ecosystem JS libraries, [WPScan Vulnerability API](https://wpscan.com/api) for WordPress core/plugins/themes
- **PII exposure scan** — emails, phone numbers, SSN-like numbers, Luhn-valid card-like numbers, leaked secrets (AWS keys, Stripe live keys, Google API keys, private key blocks, etc.)
- **Payment/donation detection** — Stripe, PayPal, Square, Donorbox, Classy, WooCommerce, Shopify Checkout, and more
- **CORS misconfiguration, mixed content, and public AI/SEO-crawler exposure** (robots.txt/llms.txt/sitemap and what they reveal)

## ⚠️ Authorized use only

This tool actively sends requests to well-known admin/login/config paths and queries third-party vulnerability databases. **Only run it against sites you own or have explicit written permission to test.** Every probe is a single unauthenticated GET to a publicly documented path — no auth bypass, brute force, fuzzing, or payload injection is performed — but unauthorized scanning of third-party infrastructure may still violate computer-fraud laws or terms of service.

## Install

```bash
pnpm install
npx playwright install chromium
```

## Usage

```bash
node scripts/run-security-audit.mjs --site https://www.example.com
```

```bash
pnpm security-audit --site https://www.example.com
```

### Flags

| Flag | Description |
| --- | --- |
| `--site <url>` | **(required)** Target website URL |
| `--max-pages <n>` | Max pages to scan (default 10) |
| `--crawl` | Discover pages by following internal links instead of using the sitemap |
| `--slow` | Conservative mode: longer waits between requests |
| `--respect-robots` | Skip URLs/paths disallowed by robots.txt |
| `--skip-exposed-paths` | Skip the admin/login/config/API path-probing phase |
| `--skip-cve` | Skip live OSV.dev/WPScan CVE lookups |
| `--wpscan-key <key>` | WPScan Vulnerability API token (or set `WPSCAN_API_KEY` env var) |

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
| `wordpress-components.csv` | Detected WP plugins/themes + versions (WordPress sites only) |
| `vulnerabilities.csv` | Matched CVEs/advisories from OSV.dev + WPScan |
| `summary.json` | Machine-readable summary: risk grade, platform, hosting, DNS, TLS, crawler exposure |

## Risk grading

Every finding is tagged `critical` / `high` / `medium` / `low` / `info`. The overall grade (A+–F) is a weighted deduction from 100 based on finding severity — mirrors the methodology used by the header-grading module (loosely modeled on securityheaders.com / Mozilla Observatory).
