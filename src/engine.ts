import { createHash } from "node:crypto";
import { type Config, matchesAny, parseConfig } from "./config.js";
import { ALL_RULES } from "./rules/index.js";
import { extractDependencies, verifyRegistry } from "./rules/supply-chain.js";
import { DOC_EXTS, type RuleContext, type RuleHit } from "./rules/types.js";
import { HUMAN_PROVENANCE } from "./provenance.js";
import type { DiffFile, Finding, Provenance, Report, Severity, Verdict } from "./types.js";
import { SEVERITY_RANK, severityAtLeast } from "./types.js";
import { VERSION } from "./version.js";

export interface AgentHook {
  (args: { files: DiffFile[]; findings: Finding[]; provenance: Provenance; config: Config }): Promise<{
    findings: Finding[];
    dismissals: { fingerprint: string; reason: string }[];
    summary: Report["agent"];
    notices?: string[];
  }>;
}

export interface ReviewInput {
  files: DiffFile[];
  provenance?: Provenance;
  config?: Config;
  target?: Report["target"];
  /** Skip network lookups (registry verification). */
  offline?: boolean;
  /** Optional agentic reviewer (see agent/reviewer.ts). */
  agent?: AgentHook;
  fetchImpl?: typeof fetch;
}

export function fingerprint(ruleId: string, file: string, snippet: string, line: number): string {
  const basis = `${ruleId}\u0000${file}\u0000${snippet ? snippet.replace(/\s+/g, " ").trim() : String(line)}`;
  return createHash("sha256").update(basis).digest("hex").slice(0, 16);
}

const SUPPRESS_RE = /ironmountain-ignore(?:\[([\w/,\s*-]+)\])?(?::\s*(.*?))?\s*(?:\*\/|-->|$)/;

function extOf(path: string): string {
  const base = path.split("/").pop() ?? "";
  if (/^(Dockerfile|Containerfile)/i.test(base)) return "dockerfile";
  const i = base.lastIndexOf(".");
  return i > 0 ? base.slice(i + 1).toLowerCase() : "";
}

/** Run all static rules against a set of diff files. Pure and synchronous. */
export function runRules(files: DiffFile[], provenance: Provenance, config: Config): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    if (file.isBinary) continue;
    const ctx: RuleContext = {
      file,
      ext: extOf(file.path),
      basename: (file.path.split("/").pop() ?? "").toLowerCase(),
      provenance,
      allFiles: files,
    };
    for (const rule of ALL_RULES) {
      const override = config.rules[rule.id];
      if (override === "off" || (typeof override === "object" && override.enabled === false)) continue;
      if (typeof override === "object" && override.paths && !matchesAny(file.path, override.paths)) continue;
      if (DOC_EXTS.has(ctx.ext) && !rule.scansDocs && rule.category !== "secrets") continue;
      if (rule.appliesTo && !rule.appliesTo(ctx)) continue;
      let hits: RuleHit[];
      try {
        hits = rule.check(ctx);
      } catch (err) {
        hits = [];
        process.emitWarning(`rule ${rule.id} failed on ${file.path}: ${(err as Error).message}`);
      }
      for (const h of hits) {
        let sev: Severity = h.severity ?? rule.severity;
        if (typeof override === "string") sev = override as Severity;
        else if (typeof override === "object" && override.severity) sev = override.severity;
        const snippet = h.snippet ?? file.added.find((l) => l.line === h.line)?.content.trim().slice(0, 240) ?? "";
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          severity: sev,
          category: rule.category,
          confidence: h.confidence ?? rule.confidence,
          file: file.path,
          line: h.line,
          message: h.message ?? rule.description,
          snippet,
          remediation: rule.remediation,
          ...(rule.cwe ? { cwe: rule.cwe } : {}),
          source: "static",
          fingerprint: fingerprint(rule.id, file.path, snippet, h.line),
        });
      }
    }
  }
  return findings;
}

function applySuppressions(findings: Finding[], files: DiffFile[], provenance: Provenance, config: Config, notices: string[]) {
  const byPath = new Map(files.map((f) => [f.path, new Map(f.added.map((l) => [l.line, l.content]))]));
  for (const f of findings) {
    if (f.suppressed) continue;
    // Config-level accepted risks
    const ig = config.ignore.find((i) => (!i.rule || i.rule === f.ruleId || f.ruleId.startsWith(i.rule + "/")) && (!i.path || matchesAny(f.file, [i.path])));
    if (ig) {
      f.suppressed = { by: "config", reason: ig.reason };
      continue;
    }
    // Inline: same line or the line above
    const lines = byPath.get(f.file);
    for (const ln of [f.line, f.line - 1]) {
      const text = lines?.get(ln);
      if (!text) continue;
      const m = SUPPRESS_RE.exec(text);
      if (!m) continue;
      const ruleList = m[1]?.split(",").map((s) => s.trim());
      if (ruleList && !ruleList.some((r) => r === "*" || r === f.ruleId || f.ruleId.startsWith(r + "/"))) continue;
      const reason = (m[2] ?? "").trim();
      if (!reason && provenance.aiAuthored && config.ai.requireSuppressionReason) {
        notices.push(`Ignored reason-less suppression for ${f.ruleId} at ${f.file}:${f.line} (AI-authored change).`);
        continue;
      }
      if (f.severity === "critical" && f.category === "secrets") {
        notices.push(`Inline suppression cannot hide a committed secret (${f.file}:${f.line}).`);
        continue;
      }
      f.suppressed = { by: "inline", reason: reason || "(no reason given)" };
      break;
    }
  }
}

const WEIGHT: Record<Severity, number> = { critical: 40, high: 15, medium: 5, low: 1, info: 0 };

export function computeVerdict(findings: Finding[], provenance: Provenance, config: Config): { verdict: Verdict; riskScore: number; gate: Report["gate"] } {
  const failOn = provenance.aiAuthored ? config.ai.failOn : config.failOn;
  const warnOn = provenance.aiAuthored ? config.ai.warnOn : config.warnOn;
  const active = findings.filter((f) => !f.suppressed);
  const blocking = active.filter((f) => severityAtLeast(f.severity, failOn));
  const warning = active.filter((f) => severityAtLeast(f.severity, warnOn));
  let score = active.reduce((s, f) => s + WEIGHT[f.severity] * (f.confidence === "low" ? 0.5 : 1), 0);
  if (provenance.aiAuthored) score *= 1.25;
  const riskScore = Math.min(100, Math.round(score));
  const verdict: Verdict = blocking.length ? "block" : warning.length ? "warn" : "pass";
  const who = provenance.aiAuthored ? `AI-authored change (${provenance.agents.join(", ")}) policy` : "standard policy";
  const reason = blocking.length
    ? `${blocking.length} finding(s) at or above "${failOn}" under ${who}`
    : warning.length
      ? `${warning.length} finding(s) at or above "${warnOn}" under ${who}`
      : `no findings at or above "${warnOn}" under ${who}`;
  return { verdict, riskScore, gate: { failOn, warnOn, reason } };
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      Number(!!a.suppressed) - Number(!!b.suppressed) ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );
}

/** Full review pipeline: static rules, registry checks, optional agent, policy gate. */
export async function review(input: ReviewInput): Promise<Report> {
  const started = Date.now();
  const config = input.config ?? parseConfig({});
  const provenance = input.provenance ?? HUMAN_PROVENANCE;
  const notices: string[] = [];
  const files = input.files.filter((f) => !matchesAny(f.path, config.exclude));

  let findings = runRules(files, provenance, config);

  if (config.supplyChain.verifyRegistry && !input.offline) {
    const deps = extractDependencies(files);
    if (deps.length) {
      const results = await verifyRegistry(deps, { newPackageDays: config.supplyChain.newPackageDays, ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}) });
      const unknown = results.filter((r) => r.status === "unknown").length;
      if (unknown) notices.push(`Could not verify ${unknown} dependenc${unknown === 1 ? "y" : "ies"} against the registry (offline or rate-limited).`);
      for (const r of results) {
        if (r.status !== "missing" && r.status !== "new") continue;
        const missing = r.status === "missing";
        const ruleId = missing ? "supply-chain/nonexistent-package" : "supply-chain/new-package";
        const snippet = `"${r.dep.name}": "${r.dep.spec}"`;
        findings.push({
          ruleId,
          title: missing ? "Dependency does not exist on the registry" : "Dependency is a brand-new package",
          severity: missing ? "critical" : "medium",
          category: "supply-chain",
          confidence: "high",
          file: r.dep.file,
          line: r.dep.line,
          message: missing
            ? `\`${r.dep.name}\` is not published on ${r.dep.ecosystem === "npm" ? "npm" : "PyPI"}. AI assistants hallucinate package names, and attackers register them ("slopsquatting"). Installing this later could pull attacker code.`
            : `\`${r.dep.name}\` was first published ${r.createdAt?.slice(0, 10)}, less than ${config.supplyChain.newPackageDays} days ago. New packages are a common malware vector.`,
          snippet,
          remediation: "Verify the intended package name and publisher before installing; prefer established, maintained packages.",
          cwe: ["CWE-1357", "CWE-829"],
          source: "static",
          fingerprint: fingerprint(ruleId, r.dep.file, snippet, r.dep.line),
        });
      }
    }
  }

  let agentSummary: Report["agent"];
  if (input.agent) {
    try {
      const res = await input.agent({ files, findings, provenance, config });
      agentSummary = res.summary;
      notices.push(...(res.notices ?? []));
      const nonDismissible = new Set(config.agent.nonDismissible);
      for (const d of res.dismissals) {
        const f = findings.find((x) => x.fingerprint === d.fingerprint);
        if (!f) continue;
        if (nonDismissible.has(f.category) || f.severity === "critical") {
          notices.push(`AI reviewer tried to dismiss ${f.ruleId} at ${f.file}:${f.line}; denied by policy (${f.severity}/${f.category} findings need a human).`);
          continue;
        }
        f.suppressed = { by: "agent", reason: d.reason };
      }
      findings.push(...res.findings);
    } catch (err) {
      notices.push(`Agentic review failed: ${(err as Error).message}. Static results are still enforced.`);
    }
  }

  applySuppressions(findings, files, provenance, config, notices);

  // Dedupe (same rule, same location)
  const seen = new Set<string>();
  findings = findings.filter((f) => {
    const k = `${f.ruleId}|${f.file}|${f.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  findings = sortFindings(findings);

  const { verdict, riskScore, gate } = computeVerdict(findings, provenance, config);
  return {
    tool: { name: "ironmountain", version: VERSION },
    createdAt: new Date().toISOString(),
    target: input.target ?? { description: `${files.length} file(s)` },
    verdict,
    riskScore,
    gate,
    provenance,
    findings,
    stats: {
      filesChanged: files.length,
      linesAdded: files.reduce((s, f) => s + f.added.length, 0),
      linesRemoved: files.reduce((s, f) => s + f.removed.length, 0),
      rulesRun: ALL_RULES.length,
      durationMs: Date.now() - started,
    },
    ...(agentSummary ? { agent: agentSummary } : {}),
    notices,
  };
}
