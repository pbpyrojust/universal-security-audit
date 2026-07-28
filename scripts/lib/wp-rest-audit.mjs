// ── Authenticated WordPress audit via the official REST API + Application Passwords, instead of
// scraping wp-admin HTML. This is the preferred path when an Application Password is supplied: it's
// stable across WP core/admin-theme changes, doesn't need Playwright at all, and only reads data the
// authenticated user already has REST capability to see (edit_plugins/list_users/etc). ──

function authHeader(appUser, appPassword) {
  const token = Buffer.from(`${appUser}:${appPassword}`).toString('base64');
  return { Authorization: `Basic ${token}`, 'user-agent': 'Universal-Security-Audit' };
}

async function restGet(origin, path, appUser, appPassword, { timeoutMs = 15000 } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(new URL(path, origin).toString(), { headers: authHeader(appUser, appPassword), signal: controller.signal });
    clearTimeout(t);
    if (!res.ok) return { ok: false, status: res.status, error: await res.text().catch(() => '') };
    return { ok: true, status: res.status, data: await res.json() };
  } catch (e) {
    clearTimeout(t);
    return { ok: false, status: 0, error: String(e?.message || e) };
  }
}

export async function verifyWpAppCredentials(origin, appUser, appPassword) {
  const res = await restGet(origin, '/wp-json/wp/v2/users/me?context=edit', appUser, appPassword);
  return { ok: res.ok, roles: res.ok ? res.data.roles || [] : [], error: res.error };
}

export async function wpRestPlugins(origin, appUser, appPassword) {
  const res = await restGet(origin, '/wp-json/wp/v2/plugins', appUser, appPassword);
  if (!res.ok) return { ok: false, error: res.error, plugins: [] };
  const plugins = (res.data || []).map((p) => ({
    slug: String(p.plugin || '').split('/')[0],
    name: p.name?.replace(/<[^>]+>/g, '') || p.plugin,
    active: p.status === 'active',
    version: p.version || null,
  }));
  return { ok: true, plugins };
}

export async function wpRestThemes(origin, appUser, appPassword) {
  const res = await restGet(origin, '/wp-json/wp/v2/themes?status=active,inactive', appUser, appPassword);
  if (!res.ok) return { ok: false, error: res.error, themes: [] };
  const themes = (res.data || []).map((t) => ({
    slug: t.stylesheet,
    name: t.name?.rendered || t.name?.raw || t.stylesheet,
    active: t.status === 'active',
    version: t.version || null,
  }));
  return { ok: true, themes };
}

export async function wpRestUsers(origin, appUser, appPassword) {
  const res = await restGet(origin, '/wp-json/wp/v2/users?context=edit&per_page=100', appUser, appPassword);
  if (!res.ok) return { ok: false, error: res.error, users: [] };
  const users = (res.data || []).map((u) => ({ username: u.slug || u.name, role: (u.roles || []).join(', ') }));
  return { ok: true, users };
}
