/**
 * security.txt (RFC 9116): how researchers report vulnerabilities to you.
 *
 * Looks for /.well-known/security.txt (the RFC's location), falling back to
 * /security.txt (legacy), and validates what the RFC requires:
 *  - Contact: at least one (mailto:, https: or tel: URI)
 *  - Expires: exactly one, an ISO 8601 date in the future (the RFC
 *    recommends less than a year ahead)
 *  - served over HTTPS as text/plain
 *  - Canonical, if present, should include the URL it was fetched from
 * and notes the optional fields (Policy, Encryption, Acknowledgments,
 * Preferred-Languages, Hiring) and whether it's PGP-signed.
 */
export async function checkSecurityTxt(origin, { timeoutMs = 8000, now = new Date() } = {}) {
  const candidates = ['/.well-known/security.txt', '/security.txt'];
  for (const path of candidates) {
    const url = new URL(path, origin).toString();
    let res;
    let text = '';
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      res = await fetch(url, { redirect: 'follow', signal: ctrl.signal, headers: { 'user-agent': 'Universal-Security-Audit security.txt check' } });
      clearTimeout(timer);
      text = res.ok ? await res.text() : '';
    } catch {
      continue;
    }
    if (!res.ok || !text.trim() || /<html|<!doctype/i.test(text.slice(0, 200))) continue;
    return { found: true, url, legacyLocation: path === '/security.txt', ...validate(text, url, res, now) };
  }
  return { found: false, url: new URL(candidates[0], origin).toString(), problems: [], warnings: [], fields: {} };
}

function validate(text, url, res, now) {
  const signed = text.includes('-----BEGIN PGP SIGNED MESSAGE-----');
  const fields = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-----')) continue;
    const i = line.indexOf(':');
    if (i < 1) continue;
    const key = line.slice(0, i).trim().toLowerCase();
    (fields[key] ||= []).push(line.slice(i + 1).trim());
  }
  const problems = [];
  const warnings = [];
  const contacts = fields.contact || [];
  if (!contacts.length) problems.push('No Contact field (required): add at least one, e.g. "Contact: mailto:security@example.com".');
  for (const c of contacts) {
    if (!/^(mailto:|https:|tel:)/i.test(c)) problems.push(`Contact "${c}" isn't a mailto:, https: or tel: URI.`);
  }
  const expires = fields.expires || [];
  if (!expires.length) problems.push('No Expires field (required): add one, e.g. "Expires: 2027-06-30T00:00:00Z".');
  else if (expires.length > 1) problems.push('More than one Expires field (only one is allowed).');
  else {
    const when = new Date(expires[0]);
    if (Number.isNaN(when.getTime())) problems.push(`Expires "${expires[0]}" isn't a valid ISO 8601 date.`);
    else if (when <= now) problems.push(`Expired on ${when.toISOString().slice(0, 10)}: researchers are told to treat the file as stale. Update Expires.`);
    else if (when - now > 366 * 86400000) warnings.push(`Expires is more than a year ahead (${when.toISOString().slice(0, 10)}); the RFC recommends under a year so the file gets reviewed.`);
  }
  if (!url.startsWith('https:')) problems.push('Served over plain HTTP; security.txt must be served over HTTPS.');
  const type = res.headers.get('content-type') || '';
  if (!/^text\/plain/i.test(type)) warnings.push(`Content-Type is "${type || 'missing'}"; it should be text/plain; charset=utf-8.`);
  const canonical = fields.canonical || [];
  if (canonical.length && !canonical.some((c) => c.replace(/\/$/, '') === url.replace(/\/$/, ''))) warnings.push(`Canonical (${canonical.join(', ')}) doesn't list the URL it was served from (${url}).`);
  if (!fields.policy) warnings.push('No Policy field: link to a vulnerability disclosure policy so researchers know the rules.');
  return { problems, warnings, signed, fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, v.join(' | ')])) };
}
