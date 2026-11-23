import { ALL_RULES } from "../rules/index.js";
import type { Report, Severity } from "../types.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SCORE: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "0.0" };

/** SARIF 2.1.0 for GitHub code scanning and other SAST dashboards. */
export function toSarif(report: Report): object {
  const ruleIds = [...new Set(report.findings.map((f) => f.ruleId))];
  const rules = ruleIds.map((id) => {
    const r = ALL_RULES.find((x) => x.id === id);
    const sample = report.findings.find((f) => f.ruleId === id)!;
    return {
      id,
      name: id.replace(/[^A-Za-z0-9]+/g, "_"),
      shortDescription: { text: r?.title ?? sample.title },
      fullDescription: { text: r?.description ?? sample.message },
      help: { text: r?.remediation ?? sample.remediation ?? "", markdown: r?.remediation ?? sample.remediation ?? "" },
      defaultConfiguration: { level: LEVEL[r?.severity ?? sample.severity] },
      properties: {
        tags: ["security", sample.category, ...(sample.cwe ?? []).map((c) => `external/cwe/${c.toLowerCase()}`)],
        "security-severity": SCORE[r?.severity ?? sample.severity],
        precision: (r?.confidence ?? sample.confidence) === "high" ? "high" : (r?.confidence ?? sample.confidence) === "medium" ? "medium" : "low",
      },
    };
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Iron Mountain",
            semanticVersion: report.tool.version,
            informationUri: "https://github.com/airostudio/ironmountain",
            rules,
          },
        },
        automationDetails: { id: `ironmountain/${report.target.description}` },
        properties: { verdict: report.verdict, riskScore: report.riskScore, aiAuthored: report.provenance.aiAuthored, agents: report.provenance.agents },
        results: report.findings.map((f) => ({
          ruleId: f.ruleId,
          ruleIndex: ruleIds.indexOf(f.ruleId),
          level: LEVEL[f.severity],
          message: { text: `${f.title}: ${f.message}` },
          locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: Math.max(1, f.line) } } }],
          partialFingerprints: { ironmountain: f.fingerprint },
          properties: { severity: f.severity, confidence: f.confidence, source: f.source },
          ...(f.suppressed ? { suppressions: [{ kind: f.suppressed.by === "inline" ? "inSource" : "external", justification: f.suppressed.reason }] } : {}),
        })),
      },
    ],
  };
}
