// ── Authenticated Drupal admin audit. Requires the caller to already be logged in (via
// maybePerformFormLogin against /user/login). Drupal's admin theme/markup varies more across
// versions/installs than WordPress's, so parsing here leans on visible text (innerText) and Drupal
// core's default Views field classes rather than brittle theme-specific selectors — best-effort,
// same "just read what a logged-in admin can already see" philosophy as the WP audit. ──

export async function isLoggedIntoDrupalAdmin(page, origin) {
  try {
    const res = await page.goto(new URL('/user', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    const url = page.url();
    return !/\/user\/login/i.test(url) && (res?.status?.() ?? 200) < 400;
  } catch { return false; }
}

export async function scanDrupalStatusReport(page, origin) {
  const result = { drupalVersion: null, phpVersion: null, dbVersion: null, errorCount: 0, warningCount: 0, errorItems: [] };
  try {
    await page.goto(new URL('/admin/reports/status', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    const text = await page.evaluate(() => document.body.innerText);
    const drupalM = /Drupal (?:Version|core version)\s*\n?\s*([\d.]+)/i.exec(text);
    if (drupalM) result.drupalVersion = drupalM[1];
    const phpM = /\bPHP\b\s*\n?\s*([\d.]+)/i.exec(text);
    if (phpM) result.phpVersion = phpM[1];
    const dbM = /Database\s*\n?\s*(MySQL|MariaDB|PostgreSQL|SQLite)?\s*([\d.]+)/i.exec(text);
    if (dbM) result.dbVersion = [dbM[1], dbM[2]].filter(Boolean).join(' ');
    result.errorCount = (text.match(/\bError\b/g) || []).length;
    result.warningCount = (text.match(/\bWarning\b/g) || []).length;
    const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
    result.errorItems = lines.filter((l) => /^Error\b/.test(l)).slice(0, 20);
  } catch {}
  return result;
}

export async function scanDrupalModules(page, origin) {
  try {
    await page.goto(new URL('/admin/modules', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    return await page.$$eval('input[type=checkbox][name^="modules["]', (checkboxes) => checkboxes.map((cb) => {
      const nameMatch = /^modules\[([^\]]+)\]/.exec(cb.getAttribute('name') || '');
      const machineName = nameMatch ? nameMatch[1] : '';
      const row = cb.closest('tr') || cb.closest('.form-item')?.parentElement || cb.parentElement;
      const rowText = row ? row.innerText : '';
      const versionMatch = /(\d+\.x-\d+\.[\d.]+|\d+\.\d+\.\d+)/.exec(rowText);
      const nameEl = row?.querySelector('label, .module-name, td strong, strong');
      return {
        slug: machineName,
        name: nameEl ? nameEl.textContent.trim().split('\n')[0] : machineName,
        enabled: cb.checked,
        version: versionMatch ? versionMatch[1] : null,
      };
    }).filter((m) => m.slug));
  } catch { return []; }
}

export async function scanDrupalUsers(page, origin) {
  try {
    await page.goto(new URL('/admin/people', origin).toString(), { waitUntil: 'domcontentloaded', timeout: 30000 });
    return await page.$$eval('tr', (rows) => rows.map((row) => {
      const nameEl = row.querySelector('.views-field-name a, td.views-field-name');
      const rolesEl = row.querySelector('.views-field-roles');
      const statusEl = row.querySelector('.views-field-status');
      if (!nameEl) return null;
      return {
        username: nameEl.textContent.trim(),
        roles: rolesEl ? rolesEl.textContent.trim().replace(/\s+/g, ' ') : '',
        status: statusEl ? statusEl.textContent.trim() : '',
      };
    }).filter(Boolean));
  } catch { return []; }
}

const EOL_PHP_MINORS = new Set(['5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1']);
export function checkPhpEol(phpVersion) {
  if (!phpVersion) return null;
  const minor = (phpVersion.match(/^(\d+\.\d+)/) || [])[1];
  return minor ? EOL_PHP_MINORS.has(minor) : null;
}

// Drupal core major versions no longer receiving security coverage (checked against the major.minor).
const EOL_DRUPAL_MAJORS = new Set(['6', '7', '8', '9']);
export function checkDrupalCoreEol(drupalVersion) {
  if (!drupalVersion) return null;
  const major = (drupalVersion.match(/^(\d+)/) || [])[1];
  return major ? EOL_DRUPAL_MAJORS.has(major) : null;
}
