export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function severityAtLeast(sev: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[sev] >= SEVERITY_RANK[threshold];
}

export type Category =
  | "secrets"
  | "injection"
  | "crypto"
  | "web"
  | "config"
  | "supply-chain"
  | "ci"
  | "infra"
  | "ai-integrity"
  | "data-exposure"
  | "logic";

export type Confidence = "high" | "medium" | "low";

/** A line that exists in the new version of a file. */
export interface DiffLine {
  /** 1-based line number in the new file (for removed lines: in the old file). */
  line: number;
  content: string;
}

export interface Hunk {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
  header: string;
}

export type FileStatus = "added" | "modified" | "deleted" | "renamed";

export interface DiffFile {
  path: string;
  oldPath?: string;
  status: FileStatus;
  isBinary: boolean;
  hunks: Hunk[];
  added: DiffLine[];
  removed: DiffLine[];
  /** Mode change to an executable / symlink etc. */
  newMode?: string;
}

export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  category: Category;
  confidence: Confidence;
  file: string;
  line: number;
  message: string;
  snippet?: string;
  remediation?: string;
  cwe?: string[];
  /** Where the finding came from. */
  source: "static" | "agent";
  /** Stable id used for dedupe, suppression and agent triage. */
  fingerprint: string;
  /** Present when the finding was suppressed or dismissed; such findings never gate. */
  suppressed?: { by: "inline" | "config" | "agent"; reason: string };
}

export type AgentName =
  | "claude"
  | "copilot"
  | "cursor"
  | "codex"
  | "gemini"
  | "devin"
  | "aider"
  | "windsurf"
  | "amazon-q"
  | "jules"
  | "other-ai";

export interface Provenance {
  aiAuthored: boolean;
  agents: AgentName[];
  evidence: string[];
}

export type Verdict = "pass" | "warn" | "block";

export interface ReviewStats {
  filesChanged: number;
  linesAdded: number;
  linesRemoved: number;
  rulesRun: number;
  durationMs: number;
}

export interface AgentSummary {
  model: string;
  summary: string;
  walkthrough: { file: string; change: string }[];
  toolCalls: number;
  stopReason: string | null;
  error?: string;
}

export interface Report {
  tool: { name: "ironmountain"; version: string };
  createdAt: string;
  target: { base?: string; head?: string; description: string };
  verdict: Verdict;
  riskScore: number;
  gate: { failOn: Severity; warnOn: Severity; reason: string };
  provenance: Provenance;
  findings: Finding[];
  stats: ReviewStats;
  agent?: AgentSummary;
  notices: string[];
}
