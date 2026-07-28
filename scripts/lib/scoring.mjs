// ── Aggregate findings into severity buckets + an overall A-F risk grade ──

export const SEVERITY_WEIGHTS = { critical: 25, high: 12, medium: 5, low: 2, info: 0 };
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function tallyBySeverity(findings = []) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const sev = SEVERITY_WEIGHTS[f.severity] != null ? f.severity : 'info';
    counts[sev]++;
  }
  return counts;
}

export function computeRiskGrade(findings = []) {
  const counts = tallyBySeverity(findings);
  let score = 100;
  for (const sev of SEVERITY_ORDER) score -= counts[sev] * SEVERITY_WEIGHTS[sev];
  score = Math.max(0, Math.min(100, score));
  const grade = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';
  return { score, grade, counts, total: findings.length };
}

export function sortFindingsBySeverity(findings = []) {
  return [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}
