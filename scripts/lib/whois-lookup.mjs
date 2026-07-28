// ── Domain registration lookup via RDAP (the modern, HTTP/JSON successor to WHOIS). Uses rdap.org's
// bootstrap redirector so we never need to know which registry serves a given TLD, and never need
// to shell out to a system `whois` binary that may not exist on the host (containers, Windows, etc). ──

function findValue(entities, role, key) {
  const entity = (entities || []).find((e) => (e.roles || []).includes(role));
  return entity?.vcardArray?.[1]?.find((f) => f[0] === key)?.[3] || null;
}

export async function rdapLookup(domain, { timeoutMs = 10000 } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { 'user-agent': 'Universal-Security-Audit', accept: 'application/rdap+json' },
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(t);
    if (!res.ok) return { checked: false, error: `HTTP ${res.status}` };
    const data = await res.json();
    const events = data.events || [];
    const registration = events.find((e) => e.eventAction === 'registration')?.eventDate || null;
    const expiration = events.find((e) => e.eventAction === 'expiration')?.eventDate || null;
    const lastChanged = events.find((e) => e.eventAction === 'last changed')?.eventDate || null;
    const registrar = findValue(data.entities, 'registrar', 'fn') || data.entities?.find((e) => (e.roles || []).includes('registrar'))?.handle || null;
    const registrantOrg = findValue(data.entities, 'registrant', 'org') || findValue(data.entities, 'registrant', 'fn');
    const nameservers = (data.nameservers || []).map((ns) => ns.ldhName).filter(Boolean);
    const statuses = data.status || [];

    let daysUntilExpiration = null;
    if (expiration) daysUntilExpiration = Math.round((new Date(expiration) - Date.now()) / (1000 * 60 * 60 * 24));

    return {
      checked: true, registrar, registrantOrg: registrantOrg || null, registration, expiration, lastChanged,
      nameservers, statuses, daysUntilExpiration,
      isExpiringSoon: daysUntilExpiration != null && daysUntilExpiration >= 0 && daysUntilExpiration < 30,
      isExpired: daysUntilExpiration != null && daysUntilExpiration < 0,
    };
  } catch (e) {
    clearTimeout(t);
    return { checked: false, error: String(e?.message || e) };
  }
}
