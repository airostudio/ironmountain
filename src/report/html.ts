import type { Report, Severity } from "../types.js";

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);

/** Self-contained HTML report (no external assets, safe to attach to CI artifacts). */
export function toHtml(report: Report): string {
  const sevs: Severity[] = ["critical", "high", "medium", "low", "info"];
  const active = report.findings.filter((f) => !f.suppressed);
  const rows = report.findings
    .map(
      (f) => `<article class="f ${f.severity}${f.suppressed ? " sup" : ""}" data-sev="${f.severity}">
  <header><span class="sev">${f.severity}</span><b>${escapeHtml(f.title)}</b><code>${escapeHtml(f.ruleId)}</code>${f.source === "agent" ? '<span class="tag">AI reviewer</span>' : ""}${f.suppressed ? `<span class="tag">suppressed: ${escapeHtml(f.suppressed.reason)}</span>` : ""}</header>
  <div class="loc">${escapeHtml(f.file)}:${f.line}</div>
  ${f.snippet ? `<pre>${escapeHtml(f.snippet)}</pre>` : ""}
  <p>${escapeHtml(f.message)}</p>
  ${f.remediation ? `<p class="fix"><b>Fix:</b> ${escapeHtml(f.remediation)}</p>` : ""}
</article>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Iron Mountain Review</title>
<style>
:root{--bg:#f7f7f5;--fg:#1d1d1f;--muted:#6b6b70;--card:#fff;--line:#e3e3e0;--crit:#b4232a;--high:#d9480f;--med:#c48a00;--low:#1c7ed6;--info:#5c7cfa;--ok:#2b8a3e}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececef;--muted:#9a9aa2;--card:#1d1d21;--line:#2c2c31}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}.muted{color:var(--muted)}
.verdict{display:inline-block;padding:4px 12px;border-radius:6px;font-weight:700;color:#fff}.block{background:var(--crit)}.warn{background:var(--med)}.pass{background:var(--ok)}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:96px}.stat b{display:block;font-size:20px}
.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;padding:12px 14px;margin:10px 0}.f.critical{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}.f.medium{border-left-color:var(--med)}.f.low{border-left-color:var(--low)}.f.sup{opacity:.55}
.f header{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.sev{text-transform:uppercase;font-size:11px;font-weight:700;letter-spacing:.04em}.tag{font-size:12px;border:1px solid var(--line);border-radius:999px;padding:0 8px;color:var(--muted)}
code,pre,.loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}.loc{color:var(--muted)}pre{background:var(--bg);padding:8px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.ai{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:12px 0}
</style></head><body><main>
<h1>🏔️ Iron Mountain review</h1>
<div class="muted">${escapeHtml(report.target.description)} · ${escapeHtml(report.createdAt)}</div>
<p><span class="verdict ${report.verdict}">${report.verdict.toUpperCase()}</span> &nbsp;risk ${report.riskScore}/100 · ${escapeHtml(report.gate.reason)}</p>
${report.provenance.aiAuthored ? `<div class="ai">🤖 <b>AI-authored change</b> (${escapeHtml(report.provenance.agents.join(", "))}). ${escapeHtml(report.provenance.evidence.join("; "))}</div>` : ""}
${report.agent?.summary ? `<div class="ai"><b>AI review summary</b><p>${escapeHtml(report.agent.summary)}</p></div>` : ""}
<div class="stats">${sevs.map((s) => `<div class="stat"><b>${active.filter((f) => f.severity === s).length}</b>${s}</div>`).join("")}<div class="stat"><b>${report.stats.filesChanged}</b>files</div></div>
${rows || "<p>No findings.</p>"}
${report.notices.length ? `<h3>Notices</h3><ul>${report.notices.map((n) => `<li>${escapeHtml(n)}</li>`).join("")}</ul>` : ""}
</main></body></html>`;
}
