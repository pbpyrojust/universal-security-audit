// ── Mildly-intrusive exposed-path probing: admin/login pages, backup/config leaks, exposed APIs ──
// Every probe here is a single unauthenticated GET request to a well-known, publicly documented path —
// equivalent to what any search engine or casual visitor could trigger by guessing a URL. No auth
// bypass, fuzzing, brute force, or payload injection is performed.

export const ADMIN_LOGIN_PATHS = [
  { path: '/wp-login.php', label: 'WordPress login', platform: 'WordPress' },
  { path: '/wp-admin/', label: 'WordPress admin', platform: 'WordPress' },
  { path: '/administrator/', label: 'Joomla admin', platform: 'Joomla' },
  { path: '/user/login', label: 'Drupal login', platform: 'Drupal' },
  { path: '/admin/', label: 'Generic admin path', platform: 'Generic' },
  { path: '/admin/login', label: 'Generic admin login', platform: 'Generic' },
  { path: '/login', label: 'Generic login', platform: 'Generic' },
  { path: '/cpanel', label: 'cPanel', platform: 'Hosting panel' },
  { path: '/phpmyadmin/', label: 'phpMyAdmin', platform: 'DB admin' },
  { path: '/adminer.php', label: 'Adminer DB admin', platform: 'DB admin' },
  { path: '/craft/admin', label: 'Craft CMS admin', platform: 'Craft CMS' },
  { path: '/umbraco/', label: 'Umbraco admin', platform: 'Umbraco' },
  { path: '/typo3/', label: 'TYPO3 admin', platform: 'TYPO3' },
];

export const EXPOSED_FILE_PATHS = [
  { path: '/.env', label: 'Environment file (secrets/credentials)', severity: 'critical' },
  { path: '/.git/config', label: 'Exposed .git directory', severity: 'critical' },
  { path: '/.git/HEAD', label: 'Exposed .git directory', severity: 'critical' },
  { path: '/wp-config.php.bak', label: 'WordPress config backup', severity: 'critical' },
  { path: '/wp-config.php~', label: 'WordPress config backup (editor swap)', severity: 'critical' },
  { path: '/wp-config.old', label: 'WordPress config backup', severity: 'critical' },
  { path: '/config.php.bak', label: 'Config backup file', severity: 'critical' },
  { path: '/settings.php.bak', label: 'Drupal settings backup', severity: 'critical' },
  { path: '/.DS_Store', label: 'macOS .DS_Store (reveals directory listing)', severity: 'low' },
  { path: '/backup.zip', label: 'Backup archive', severity: 'high' },
  { path: '/backup.sql', label: 'Database backup', severity: 'critical' },
  { path: '/database.sql', label: 'Database backup', severity: 'critical' },
  { path: '/dump.sql', label: 'Database dump', severity: 'critical' },
  { path: '/.htpasswd', label: 'htpasswd credential file', severity: 'critical' },
  { path: '/composer.json', label: 'Composer manifest (reveals dependency versions)', severity: 'low' },
  { path: '/package.json', label: 'npm manifest (reveals dependency versions)', severity: 'low' },
  { path: '/phpinfo.php', label: 'phpinfo() disclosure', severity: 'high' },
  { path: '/info.php', label: 'phpinfo() disclosure', severity: 'high' },
  { path: '/server-status', label: 'Apache server-status', severity: 'high' },
  { path: '/.well-known/security.txt', label: 'security.txt (informational, not a leak)', severity: 'info' },
  { path: '/error_log', label: 'Exposed PHP error log', severity: 'high' },
  { path: '/debug.log', label: 'Exposed debug log', severity: 'medium' },
];

export const EXPOSED_API_PATHS = [
  { path: '/wp-json/', label: 'WordPress REST API root', severity: 'info' },
  { path: '/wp-json/wp/v2/users', label: 'WordPress REST API user enumeration', severity: 'medium' },
  { path: '/xmlrpc.php', label: 'WordPress XML-RPC (brute-force/amplification vector)', severity: 'medium' },
  { path: '/graphql', label: 'Exposed GraphQL endpoint (check introspection)', severity: 'medium' },
  { path: '/api/', label: 'Generic API root', severity: 'info' },
  { path: '/api/users', label: 'Generic user-listing API', severity: 'medium' },
  { path: '/.well-known/change-password', label: 'Change-password well-known (informational)', severity: 'info' },
];

function isDirectoryListingHtml(html = '') {
  return /index of \//i.test(html) && /<title>index of/i.test(html);
}

// Loads a user-supplied wordlist file (one path per line, '#' comments and blank lines ignored) and
// turns it into probe entries alongside the curated lists. Larger lists are gated by --intensity
// concurrency/delay, same as the built-in path sets.
export function loadWordlistEntries(fs, filePath) {
  const text = fs.readFileSync(filePath, 'utf8');
  return text.split(/\r?\n/g)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => ({ path: line.startsWith('/') ? line : `/${line}`, label: `Custom wordlist entry: ${line}`, severity: 'medium' }));
}

export async function probePath(origin, entry, { timeoutMs = 8000, userAgent = 'Universal-Security-Audit' } = {}) {
  const url = new URL(entry.path, origin).toString();
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(url, { method: 'GET', redirect: 'manual', headers: { 'user-agent': userAgent }, signal: controller.signal });
    clearTimeout(t);
    const status = res.status;
    // Treat redirects to a login/home page as "not exposed" unless it's a 2xx.
    const exists = status >= 200 && status < 300;
    let bodySnippet = '';
    let directoryListing = false;
    if (exists) {
      const text = await res.text().catch(() => '');
      bodySnippet = text.slice(0, 300);
      directoryListing = isDirectoryListingHtml(text);
    }
    return { url, path: entry.path, label: entry.label, status, exists, directoryListing, severity: entry.severity, platform: entry.platform, bodySnippet };
  } catch (e) {
    return { url, path: entry.path, label: entry.label, status: 0, exists: false, error: String(e?.message || e), severity: entry.severity, platform: entry.platform };
  }
}

export async function probeAllPaths(origin, entries, { concurrency = 4, delayMs = 150, isAllowedUrl = null, onProgress = null, ...opts } = {}) {
  const results = [];
  const queue = entries.filter((e) => !isAllowedUrl || isAllowedUrl(new URL(e.path, origin).toString()));
  const total = queue.length;
  let idx = 0;
  async function worker() {
    while (idx < queue.length) {
      const entry = queue[idx++];
      const result = await probePath(origin, entry, opts);
      results.push(result);
      if (onProgress) onProgress(results.length, total, result);
      if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));
  return results;
}
