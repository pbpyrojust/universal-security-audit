// ── Authenticated WordPress wp-admin audit. Requires the caller to already be logged in
// (via maybePerformFormLogin against /wp-login.php). Every function here just navigates to a
// standard wp-admin screen the logged-in user already has access to and reads the rendered DOM —
// no privilege escalation, no writes, nothing the user couldn't see by clicking around themselves. ──

const KNOWN_SECURITY_PLUGIN_SLUGS = [
  'wordfence', 'better-wp-security', 'sucuri-scanner', 'all-in-one-wp-security-and-firewall',
  'wp-fail2ban', 'wp-simple-firewall', 'bulletproof-security', 'wp-cerber', 'wp-simple-firewall-pro',
  'ithemes-security-pro', 'malcare-security', 'shield-security', 'limit-login-attempts-reloaded',
  'two-factor', 'wp-2fa', 'defender-security',
];

export async function isLoggedIntoWpAdmin(page, origin) {
  try {
    const res = await page.goto(new URL('/wp-admin/', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    const url = page.url();
    return !/wp-login\.php/i.test(url) && (res?.status?.() ?? 200) < 400;
  } catch { return false; }
}

export async function scanWpPlugins(page, origin) {
  try {
    await page.goto(new URL('/wp-admin/plugins.php', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    return await page.$$eval('tr[data-slug]', (rows) => rows.map((row) => {
      const slug = row.getAttribute('data-slug') || '';
      const isActive = row.className.includes('active') && !row.className.includes('inactive');
      const nameEl = row.querySelector('.plugin-title strong');
      const name = nameEl ? nameEl.textContent.trim() : slug;
      const descText = row.querySelector('.plugin-version-author-uri')?.textContent || row.textContent || '';
      const verMatch = /Version\s+([\d.]+)/i.exec(descText);
      const updateRow = row.nextElementSibling;
      const updateAvailable = !!(updateRow && updateRow.className.includes('update'));
      let updateToVersion = null;
      if (updateAvailable) {
        const m = /view version\s+([\d.]+)/i.exec(updateRow.textContent || '');
        updateToVersion = m ? m[1] : null;
      }
      return { slug, name, active: isActive, version: verMatch ? verMatch[1] : null, updateAvailable, updateToVersion };
    }));
  } catch { return []; }
}

export async function scanWpThemes(page, origin) {
  try {
    await page.goto(new URL('/wp-admin/themes.php', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    const html = await page.content();
    const m = /_wpThemeSettings\s*=\s*(\{[\s\S]*?\});/.exec(html);
    if (!m) return [];
    const settings = JSON.parse(m[1]);
    const themes = settings.themes || [];
    return themes.map((t) => ({
      slug: t.id, name: t.name, version: t.version, active: !!t.active,
      updateAvailable: !!(t.update && t.update.new_version), updateToVersion: t.update?.new_version || null,
    }));
  } catch { return []; }
}

export async function scanWpCoreAndPhp(page, origin) {
  const result = { wpVersion: null, phpVersion: null, mysqlVersion: null, source: null };
  try {
    await page.goto(new URL('/wp-admin/index.php', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    const footerHtml = await page.content();
    const wpM = /Version\s+([\d.]+(?:-[\w.]+)?)/i.exec(footerHtml);
    if (wpM) { result.wpVersion = wpM[1]; result.source = 'admin footer'; }
  } catch {}
  try {
    await page.goto(new URL('/wp-admin/site-health.php?tab=debug', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    const html = await page.content();
    const phpM = /PHP [Vv]ersion<\/td>\s*<td[^>]*>\s*([\d.]+)/.exec(html) || /"php_version"[^"]*"\s*:\s*"([\d.]+)"/.exec(html);
    if (phpM) result.phpVersion = phpM[1];
    const mysqlM = /(?:MySQL|Database) [Vv]ersion<\/td>\s*<td[^>]*>\s*([\d.a-zA-Z-]+)/.exec(html);
    if (mysqlM) result.mysqlVersion = mysqlM[1];
    const wpHealthM = /WordPress [Vv]ersion<\/td>\s*<td[^>]*>\s*([\d.]+)/.exec(html);
    if (wpHealthM && !result.wpVersion) { result.wpVersion = wpHealthM[1]; result.source = 'site health'; }
  } catch {}
  return result;
}

export async function scanWpUsers(page, origin) {
  try {
    await page.goto(new URL('/wp-admin/users.php', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    return await page.$$eval('#the-list tr', (rows) => rows.map((row) => {
      const username = row.querySelector('.username strong, .column-username strong, .column-username a')?.textContent?.trim() || '';
      const role = row.querySelector('.role')?.textContent?.trim() || '';
      return { username, role };
    }).filter((u) => u.username));
  } catch { return []; }
}

export function detectSecurityPlugins(plugins = []) {
  const found = plugins.filter((p) => KNOWN_SECURITY_PLUGIN_SLUGS.includes(p.slug) && p.active);
  return found.map((p) => p.name);
}

// End-of-life minor versions per php.net/supported-versions.php. PHP 8.2's security support runs
// through Dec 2026 and is intentionally left off this list until that date passes.
const EOL_PHP_MINORS = new Set(['5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1']);
export function checkPhpEol(phpVersion) {
  if (!phpVersion) return null;
  const minor = (phpVersion.match(/^(\d+\.\d+)/) || [])[1];
  return minor ? EOL_PHP_MINORS.has(minor) : null;
}
