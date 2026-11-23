import type { Finding, Report, Severity } from "../types.js";

export const SEV_ICON: Record<Severity, string> = { critical: "🛑", high: "🔴", medium: "🟠", low: "🟡", info: "🔵" };
const VERDICT: Record<Report["verdict"], string> = { block: "⛔ **Blocked**", warn: "⚠️ **Passed with warnings**", pass: "✅ **Passed**" };

export const COMMENT_MARKER = "<!-- ironmountain:summary -->";

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const code = (s: string) => "`" + s.replace(/`/g, "ˋ") + "`";

export function findingBody(f: Finding): string {
  const parts = [
    `${SEV_ICON[f.severity]} **${f.title}** · \`${f.ruleId}\` · ${f.severity}${f.source === "agent" ? " · 🤖 AI reviewer" : ""}`,
    "",
    f.message,
  ];
  if (f.remediation) parts.push("", `**Fix:** ${f.remediation}`);
  if (f.cwe?.length) parts.push("", f.cwe.map((c) => `[${c}](https://cwe.mitre.org/data/definitions/${c.slice(4)}.html)`).join(" · "));
  parts.push("", `<sub>Suppress with a reviewed reason: \`ironmountain-ignore[${f.ruleId}]: <why this is safe>\`</sub>`);
  return parts.join("\n");
}

export function toMarkdown(report: Report, opts: { maxFindings?: number } = {}): string {
  const max = opts.maxFindings ?? 50;
  const active = report.findings.filter((f) => !f.suppressed);
  const suppressed = report.findings.filter((f) => f.suppressed);
  const counts = (["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => [s, active.filter((f) => f.severity === s).length] as const);

  const out: string[] = [COMMENT_MARKER, `## 🏔️ Iron Mountain change-safety review`, ""];
  out.push(`${VERDICT[report.verdict]} · risk score **${report.riskScore}/100** · ${esc(report.gate.reason)}`, "");

  if (report.provenance.aiAuthored) {
    out.push(`> 🤖 **AI-authored change** detected (${report.provenance.agents.join(", ")}). Stricter policy applied: block at \`${report.gate.failOn}\`, warn at \`${report.gate.warnOn}\`.`);
    out.push(`> <sub>Evidence: ${esc(report.provenance.evidence.slice(0, 4).join("; "))}</sub>`, "");
  }

  out.push(`| Severity | Count |`, `|---|---|`);
  for (const [s, n] of counts) if (n || s === "critical" || s === "high") out.push(`| ${SEV_ICON[s]} ${s} | ${n} |`);
  out.push("", `<sub>${report.stats.filesChanged} files · +${report.stats.linesAdded}/-${report.stats.linesRemoved} lines · ${report.stats.rulesRun} rules · ${report.stats.durationMs} ms${report.agent ? ` · agent ${report.agent.model}, ${report.agent.toolCalls} tool calls` : ""}</sub>`, "");

  if (report.agent?.summary) {
    out.push(`### Summary`, "", report.agent.summary, "");
    if (report.agent.walkthrough.length) {
      out.push(`<details><summary><b>Walkthrough</b> (${report.agent.walkthrough.length} files)</summary>`, "", `| File | Change |`, `|---|---|`);
      for (const w of report.agent.walkthrough) out.push(`| ${code(w.file)} | ${esc(w.change)} |`);
      out.push("", `</details>`, "");
    }
  }

  if (active.length) {
    out.push(`### Findings`, "");
    out.push(`| | Rule | Location | Issue |`, `|---|---|---|---|`);
    for (const f of active.slice(0, max)) {
      out.push(`| ${SEV_ICON[f.severity]} | \`${f.ruleId}\` | ${code(`${f.file}:${f.line}`)} | ${esc(f.title)}${f.source === "agent" ? " 🤖" : ""} |`);
    }
    if (active.length > max) out.push(``, `…and ${active.length - max} more. See the SARIF/JSON report for the full list.`);
    out.push("");
    out.push(`<details><summary><b>Details</b></summary>`, "");
    for (const f of active.slice(0, max)) {
      out.push(`#### ${code(`${f.file}:${f.line}`)}`, "", findingBody(f), "");
      if (f.snippet) out.push("```", f.snippet.replace(/```/g, "ˋˋˋ"), "```", "");
    }
    out.push(`</details>`, "");
  } else {
    out.push(`No active findings. 🎉`, "");
  }

  if (suppressed.length) {
    out.push(`<details><summary>${suppressed.length} suppressed / dismissed finding(s)</summary>`, "");
    for (const f of suppressed) out.push(`- \`${f.ruleId}\` ${code(`${f.file}:${f.line}`)}, ${f.suppressed!.by}: ${esc(f.suppressed!.reason)}`);
    out.push("", `</details>`, "");
  }
  if (report.notices.length) {
    out.push(`<details><summary>Notices (${report.notices.length})</summary>`, "", ...report.notices.map((n) => `- ${esc(n)}`), "", `</details>`, "");
  }
  out.push(`<sub>Iron Mountain v${report.tool.version} · comment \`/ironmountain review\` to re-run</sub>`);
  return out.join("\n");
}
