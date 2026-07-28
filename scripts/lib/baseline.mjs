// ── Baseline/exceptions: known-accepted findings (by a stable fingerprint of category+title+url)
// are suppressed from risk scoring and CI gating on future runs, but stay visible in the report
// marked as "suppressed" rather than silently vanishing. Same idea as .trivyignore / gitleaks
// baselines — accept a risk once with a reason, stop it from re-failing every run. ──
import crypto from 'node:crypto';

export function fingerprintFinding(f) {
  const key = `${f.category}|${f.title}|${f.url}`;
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
}

export function loadBaseline(fs, path, baselinePath) {
  if (!baselinePath) return { entries: [], accepted: new Map() };
  let data;
  try {
    data = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), baselinePath), 'utf8'));
  } catch (e) {
    throw new Error(`Could not read --baseline file: ${String(e?.message || e)}`);
  }
  const now = Date.now();
  const accepted = new Map();
  for (const entry of data.accepted || []) {
    if (entry.expires && new Date(entry.expires).getTime() < now) continue; // expired exceptions stop applying
    accepted.set(entry.fingerprint, entry);
  }
  return { entries: data.accepted || [], accepted };
}

// Returns every finding with `suppressed` + `suppressedReason` set, so callers can filter for
// scoring/CI purposes while still writing the full (marked) set to CSV/JSON/dashboard.
export function applyBaseline(findings, baseline) {
  return findings.map((f) => {
    const fp = fingerprintFinding(f);
    const entry = baseline.accepted.get(fp);
    return { ...f, fingerprint: fp, suppressed: !!entry, suppressedReason: entry?.reason || null };
  });
}
