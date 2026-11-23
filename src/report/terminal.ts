import type { Report, Severity } from "../types.js";

const useColor = () => {
  if (process.env.NO_COLOR || process.env.FORCE_COLOR === "0") return false;
  return !!process.stdout.isTTY || !!process.env.FORCE_COLOR;
};
const c = (code: string) => (s: string) => (useColor() ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = c("1");
const dim = c("2");
const COLORS: Record<Severity, (s: string) => string> = { critical: c("1;97;41"), high: c("1;31"), medium: c("33"), low: c("36"), info: c("34") };

export function toTerminal(report: Report): string {
  const out: string[] = [];
  const active = report.findings.filter((f) => !f.suppressed);
  for (const f of active) {
    out.push(`${COLORS[f.severity](` ${f.severity.toUpperCase()} `)} ${bold(f.title)} ${dim(`[${f.ruleId}]`)}${f.source === "agent" ? " (AI reviewer)" : ""}`);
    out.push(`  ${c("4")(`${f.file}:${f.line}`)}`);
    if (f.snippet) out.push(`  ${dim("│")} ${f.snippet}`);
    out.push(`  ${f.message}`);
    if (f.remediation) out.push(`  ${dim("fix:")} ${f.remediation}`);
    out.push("");
  }
  const suppressed = report.findings.length - active.length;
  if (report.agent?.summary) out.push(bold("AI review summary"), report.agent.summary, "");
  for (const n of report.notices) out.push(dim(`note: ${n}`));
  if (report.notices.length) out.push("");
  if (report.provenance.aiAuthored) out.push(`${c("35")("AI-authored")} change (${report.provenance.agents.join(", ")}); stricter policy applied.`);
  const verdict = report.verdict === "block" ? c("1;97;41")(" BLOCK ") : report.verdict === "warn" ? c("1;30;43")(" WARN ") : c("1;30;42")(" PASS ");
  out.push(
    `${verdict} ${bold(`risk ${report.riskScore}/100`)} · ${active.length} finding(s)${suppressed ? `, ${suppressed} suppressed` : ""} · ${report.stats.filesChanged} files · ${report.stats.durationMs} ms`,
  );
  out.push(dim(report.gate.reason));
  return out.join("\n");
}
