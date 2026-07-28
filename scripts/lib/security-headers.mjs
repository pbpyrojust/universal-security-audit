// ── Security response-header grading, modeled on securityheaders.com / Mozilla Observatory methodology ──

function headerVal(headers, name) {
  const v = headers.get?.(name) ?? headers[name] ?? headers[name.toLowerCase()];
  return v == null ? null : String(v);
}

export function gradeCookies(setCookieHeaders = []) {
  const findings = [];
  for (const raw of setCookieHeaders) {
    const name = raw.split('=')[0]?.trim() || 'cookie';
    const lower = raw.toLowerCase();
    const issues = [];
    if (!lower.includes('secure')) issues.push('missing Secure');
    if (!lower.includes('httponly')) issues.push('missing HttpOnly');
    if (!lower.includes('samesite')) issues.push('missing SameSite');
    if (issues.length) findings.push({ name, issues });
  }
  return findings;
}

export function gradeSecurityHeaders(headers, { isHttps = true } = {}) {
  const get = (name) => headerVal(headers, name);
  const checks = [];
  let score = 100;

  const csp = get('content-security-policy');
  if (!csp) {
    checks.push({ header: 'Content-Security-Policy', status: 'missing', severity: 'high', note: 'No CSP set — no defense-in-depth against XSS/injection.' });
    score -= 20;
  } else if (/unsafe-inline|unsafe-eval/i.test(csp)) {
    checks.push({ header: 'Content-Security-Policy', status: 'weak', severity: 'medium', note: `Present but allows 'unsafe-inline'/'unsafe-eval'.` });
    score -= 8;
  } else {
    checks.push({ header: 'Content-Security-Policy', status: 'present', severity: 'ok', note: 'Present.' });
  }

  const hsts = get('strict-transport-security');
  if (isHttps && !hsts) {
    checks.push({ header: 'Strict-Transport-Security', status: 'missing', severity: 'high', note: 'HTTPS site without HSTS — vulnerable to protocol downgrade/SSL-stripping.' });
    score -= 15;
  } else if (hsts) {
    const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] || 0);
    if (maxAge < 15552000) {
      checks.push({ header: 'Strict-Transport-Security', status: 'weak', severity: 'low', note: `max-age is only ${maxAge}s (recommended >= 6 months).` });
      score -= 4;
    } else {
      checks.push({ header: 'Strict-Transport-Security', status: 'present', severity: 'ok', note: 'Present with adequate max-age.' });
    }
  }

  const xfo = get('x-frame-options');
  const cspFrameAncestors = /frame-ancestors/i.test(csp || '');
  if (!xfo && !cspFrameAncestors) {
    checks.push({ header: 'X-Frame-Options', status: 'missing', severity: 'medium', note: 'No clickjacking protection (no X-Frame-Options or CSP frame-ancestors).' });
    score -= 10;
  } else {
    checks.push({ header: 'X-Frame-Options / frame-ancestors', status: 'present', severity: 'ok', note: 'Clickjacking protection present.' });
  }

  const xcto = get('x-content-type-options');
  if (!xcto || !/nosniff/i.test(xcto)) {
    checks.push({ header: 'X-Content-Type-Options', status: 'missing', severity: 'low', note: 'MIME-sniffing not disabled.' });
    score -= 6;
  } else {
    checks.push({ header: 'X-Content-Type-Options', status: 'present', severity: 'ok', note: 'nosniff set.' });
  }

  const refPol = get('referrer-policy');
  if (!refPol) {
    checks.push({ header: 'Referrer-Policy', status: 'missing', severity: 'low', note: 'No referrer policy — full URLs (possibly with tokens) may leak to third parties.' });
    score -= 6;
  } else {
    checks.push({ header: 'Referrer-Policy', status: 'present', severity: 'ok', note: `Set to "${refPol}".` });
  }

  const permPol = get('permissions-policy');
  if (!permPol) {
    checks.push({ header: 'Permissions-Policy', status: 'missing', severity: 'low', note: 'No restriction on powerful browser features (camera, mic, geolocation, etc).' });
    score -= 5;
  } else {
    checks.push({ header: 'Permissions-Policy', status: 'present', severity: 'ok', note: 'Present.' });
  }

  const coop = get('cross-origin-opener-policy');
  if (!coop) {
    checks.push({ header: 'Cross-Origin-Opener-Policy', status: 'missing', severity: 'low', note: 'No COOP — window.opener-based attacks (e.g. tabnabbing) not mitigated.' });
    score -= 4;
  } else {
    checks.push({ header: 'Cross-Origin-Opener-Policy', status: 'present', severity: 'ok', note: 'Present.' });
  }

  const corp = get('cross-origin-resource-policy');
  if (!corp) {
    checks.push({ header: 'Cross-Origin-Resource-Policy', status: 'missing', severity: 'info', note: 'Not set (defense-in-depth for cross-origin resource embedding).' });
    score -= 2;
  } else {
    checks.push({ header: 'Cross-Origin-Resource-Policy', status: 'present', severity: 'ok', note: 'Present.' });
  }

  const serverHeader = get('server');
  const poweredBy = get('x-powered-by');
  if (serverHeader && /\d/.test(serverHeader)) {
    checks.push({ header: 'Server', status: 'disclosure', severity: 'low', note: `Reveals version info: "${serverHeader}".` });
    score -= 3;
  }
  if (poweredBy) {
    checks.push({ header: 'X-Powered-By', status: 'disclosure', severity: 'low', note: `Reveals stack info: "${poweredBy}".` });
    score -= 3;
  }

  score = Math.max(0, Math.min(100, score));
  const grade = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, checks };
}
