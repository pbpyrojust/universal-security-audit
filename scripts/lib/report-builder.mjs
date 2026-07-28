// ── Shared HTML dashboard builder, used both inline during a live audit run and by the
// standalone scripts/generate-security-report.mjs (--run-dir) regenerator. Branding-aware so
// reports can be white-labeled the same way universal-seo-audit's generate-visual-report.mjs is. ──

export const DEFAULT_BRANDING = {
  companyName: 'Universal Security Audit',
  logo: '',
  primaryColor: '#ef4444',
  secondaryColor: '#0f172a',
  accentColor: '#22c55e',
  reportTitle: 'Security & Attack Surface Audit',
  author: '',
  footerText: '',
};

export function loadBranding(fs, path, brandConfigPath) {
  let branding = { ...DEFAULT_BRANDING };
  if (brandConfigPath) {
    try {
      const custom = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), brandConfigPath), 'utf8'));
      branding = { ...branding, ...custom };
    } catch (e) {
      console.error(`Warning: could not read --brand-config (${String(e?.message || e)}); using defaults.`);
    }
  }
  return branding;
}

function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch])); }

export function buildSecurityDashboardHtml({
  site, risk, sorted, primaryPlatform, platformSignals, hostingSignals, tlsInfo, dnsRecords,
  libraries, vulnResults, crawlerExposure, paymentProcessors, generatedAt = new Date(),
}, branding = DEFAULT_BRANDING) {
  const gradeColor = { 'A+': '#16a34a', A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444' }[risk.grade] || '#94a3b8';
  const sevColorMap = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#94a3b8' };
  const rows = sorted.map((f) => `
    <tr${f.suppressed ? ' style="opacity:.5"' : ''}>
      <td><span class="badge" style="background:${sevColorMap[f.severity]}22;color:${sevColorMap[f.severity]}">${esc(f.severity)}</span>${f.suppressed ? ' <span class="badge" style="background:#64748b22;color:#64748b" title="' + esc(f.suppressedReason || '') + '">suppressed</span>' : ''}</td>
      <td>${esc(f.category)}</td>
      <td>${esc(f.title)}</td>
      <td class="detail">${esc(f.detail)}</td>
      <td class="url">${f.url ? `<a href="${esc(f.url)}" target="_blank" rel="noopener">${esc(f.url)}</a>` : ''}</td>
    </tr>`).join('');
  const vulnRows = vulnResults.flatMap((r) => r.vulns.map((v) => `
    <tr><td>${esc(r.component)}</td><td>${esc(r.source)}</td><td>${esc(v.id || '')}</td><td>${esc(v.title || v.summary || '')}</td></tr>`)).join('');
  const logoHtml = branding.logo ? `<img src="${esc(branding.logo)}" alt="${esc(branding.companyName)} logo" class="logo">` : '';

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(branding.reportTitle)} — ${esc(site)}</title>
<style>
  :root { color-scheme: light dark; --primary: ${branding.primaryColor}; --accent: ${branding.accentColor}; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 2rem; background: #0b0f16; color: #e2e8f0; }
  .logo { max-height: 44px; max-width: 200px; object-fit: contain; display: block; margin-bottom: .75rem; }
  .masthead { background: linear-gradient(135deg, var(--primary), #1e293b); padding: 1.5rem 1.75rem; border-radius: 16px; margin-bottom: 1.5rem; box-shadow: 0 10px 30px rgba(0,0,0,.35); }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; color: #fff; }
  .sub { color: #e2e8f0cc; font-size: .85rem; }
  .grade-card { display: inline-flex; align-items: center; gap: 1rem; background: #131a24; border: 1px solid #1f2937; border-radius: 12px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }
  .grade { font-size: 2.5rem; font-weight: 800; color: ${gradeColor}; }
  .stats { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .stat { background: #131a24; border: 1px solid #1f2937; border-radius: 10px; padding: .75rem 1rem; min-width: 110px; }
  .stat .n { font-size: 1.4rem; font-weight: 700; }
  .stat .l { font-size: .75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; }
  section { margin-bottom: 2rem; }
  table { width: 100%; border-collapse: collapse; background: #131a24; border: 1px solid #1f2937; border-radius: 10px; overflow: hidden; }
  th, td { text-align: left; padding: .6rem .8rem; border-bottom: 1px solid #1f2937; font-size: .85rem; vertical-align: top; }
  th { background: #1a2230; color: #94a3b8; text-transform: uppercase; font-size: .7rem; letter-spacing: .05em; }
  .badge { padding: .15rem .5rem; border-radius: 999px; font-size: .7rem; font-weight: 700; text-transform: uppercase; }
  .detail { color: #cbd5e1; max-width: 420px; }
  .url a { color: var(--accent); word-break: break-all; }
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap: 1rem; }
  .meta-card { background: #131a24; border: 1px solid #1f2937; border-radius: 10px; padding: 1rem; }
  .meta-card h3 { margin: 0 0 .5rem; font-size: .8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; }
  .footer { margin-top: 2rem; color: #64748b; font-size: .75rem; text-align: center; }
  @media (prefers-color-scheme: light) {
    body { background: #f8fafc; color: #0f172a; }
    .grade-card, .stat, table, .meta-card { background: #fff; border-color: #e2e8f0; }
    th { background: #f1f5f9; }
    .detail { color: #334155; }
  }
  @media print { body { background: #fff; color: #0f172a; } .grade-card, .stat, table, .meta-card { background: #fff; border: 1px solid #cbd5e1; } th { background: #f1f5f9; } .detail { color: #334155; } section { break-inside: avoid-page; } }
</style></head><body>
  <div class="masthead">
    ${logoHtml}
    <h1>🛡️ ${esc(branding.reportTitle)}</h1>
    <div class="sub">${esc(site)} · ${esc(branding.companyName)}${branding.author ? ` · Prepared by ${esc(branding.author)}` : ''} · generated ${esc(new Date(generatedAt).toLocaleString())}</div>
  </div>
  <div class="grade-card"><div class="grade">${risk.grade}</div><div><div style="font-weight:600">${risk.score}/100 risk score</div><div style="color:#94a3b8;font-size:.85rem">${risk.total} finding(s) across all checks</div></div></div>
  <div class="stats">
    <div class="stat"><div class="n" style="color:${sevColorMap.critical}">${risk.counts.critical}</div><div class="l">Critical</div></div>
    <div class="stat"><div class="n" style="color:${sevColorMap.high}">${risk.counts.high}</div><div class="l">High</div></div>
    <div class="stat"><div class="n" style="color:${sevColorMap.medium}">${risk.counts.medium}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="n" style="color:${sevColorMap.low}">${risk.counts.low}</div><div class="l">Low</div></div>
    <div class="stat"><div class="n" style="color:${sevColorMap.info}">${risk.counts.info}</div><div class="l">Info</div></div>
  </div>
  <section>
    <div class="meta-grid">
      <div class="meta-card"><h3>Platform</h3>${platformSignals.map((s) => `<div>${esc(s.platform)} <span style="color:#94a3b8">(${esc(s.confidence)})</span></div>`).join('')}</div>
      <div class="meta-card"><h3>Hosting / CDN</h3>${hostingSignals.length ? hostingSignals.map((h) => `<div>${esc(h.provider)}</div>`).join('') : '<div style="color:#94a3b8">No signals detected</div>'}</div>
      <div class="meta-card"><h3>TLS</h3>${tlsInfo.ok ? `<div>${esc(tlsInfo.protocol)}</div><div>Expires in ${tlsInfo.daysRemaining}d</div><div>Issuer: ${esc(tlsInfo.issuer)}</div>` : '<div style="color:#94a3b8">Not checked / unavailable</div>'}</div>
      <div class="meta-card"><h3>DNS</h3><div>A: ${esc((dnsRecords.a || []).join(', ') || '—')}</div><div>NS: ${esc((dnsRecords.ns || []).join(', ') || '—')}</div><div>MX: ${esc((dnsRecords.mx || []).join(', ') || '—')}</div></div>
      <div class="meta-card"><h3>Crawler exposure</h3><div>robots.txt: ${crawlerExposure.hasRobots ? 'yes' : 'no'}</div><div>llms.txt: ${crawlerExposure.hasLlmsTxt ? 'yes' : 'no'}</div><div>sitemap: ${crawlerExposure.hasSitemap ? 'yes' : 'no'}</div></div>
      <div class="meta-card"><h3>Payment/donation</h3>${paymentProcessors.length ? paymentProcessors.map((p) => `<div>${esc(p)}</div>`).join('') : '<div style="color:#94a3b8">None detected</div>'}</div>
    </div>
  </section>
  <section>
    <h2>Findings</h2>
    <table><thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Detail</th><th>URL</th></tr></thead><tbody>${rows || '<tr><td colspan="5" style="text-align:center;color:#94a3b8">No findings 🎉</td></tr>'}</tbody></table>
  </section>
  ${vulnRows ? `<section><h2>Known Vulnerabilities (OSV.dev / WPScan)</h2><table><thead><tr><th>Component</th><th>Source</th><th>ID</th><th>Title</th></tr></thead><tbody>${vulnRows}</tbody></table></section>` : ''}
  <section><h3>Detected libraries</h3><table><thead><tr><th>Name</th><th>Version</th><th>Source</th></tr></thead><tbody>${libraries.map((l) => `<tr><td>${esc(l.name)}</td><td>${esc(l.version || 'unknown')}</td><td class="url">${esc(l.sourceUrl)}</td></tr>`).join('') || '<tr><td colspan="3" style="text-align:center;color:#94a3b8">None detected</td></tr>'}</tbody></table></section>
  <div class="footer">${esc(branding.footerText || '')}</div>
</body></html>`;
}
