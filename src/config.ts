import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { SEVERITIES } from "./types.js";

const severity = z.enum(SEVERITIES);

export const ConfigSchema = z
  .object({
    /** Block the change when any finding is at or above this severity. */
    failOn: severity.default("high"),
    /** Mark the review as "warn" at or above this severity. */
    warnOn: severity.default("medium"),
    /** Stricter thresholds applied automatically when a change is AI-authored. */
    ai: z
      .object({
        failOn: severity.default("medium"),
        warnOn: severity.default("low"),
        /** Require a written reason on inline suppressions added by AI agents. */
        requireSuppressionReason: z.boolean().default(true),
      })
      .prefault({}),
    /** Glob-ish path patterns that are never scanned. */
    exclude: z
      .array(z.string())
      .default(["**/node_modules/**", "**/dist/**", "**/build/**", "**/vendor/**", "**/*.min.js", "**/*.map", "**/*.snap", "**/*.lock"]),
    rules: z
      .record(
        z.string(),
        z.union([z.literal("off"), severity, z.object({ severity: severity.optional(), paths: z.array(z.string()).optional(), enabled: z.boolean().optional() })]),
      )
      .default({}),
    ignore: z
      .array(z.object({ rule: z.string().optional(), path: z.string().optional(), reason: z.string() }))
      .default([]),
    supplyChain: z
      .object({
        /** Look up new dependencies on npm/PyPI to catch hallucinated or brand-new packages. */
        verifyRegistry: z.boolean().default(true),
        newPackageDays: z.number().int().positive().default(30),
      })
      .prefault({}),
    agent: z
      .object({
        /** Run the Claude-powered agentic reviewer when credentials are available. */
        enabled: z.boolean().default(true),
        model: z.string().default("claude-opus-5-5"),
        effort: z.enum(["low", "medium", "high", "xhigh", "max"]).default("high"),
        maxToolCalls: z.number().int().positive().default(40),
        /** Static findings in these categories can never be dismissed by the AI reviewer. */
        nonDismissible: z.array(z.string()).default(["secrets", "ai-integrity", "supply-chain"]),
        instructions: z.string().optional(),
      })
      .prefault({}),
  })
  .strict();

export type Config = z.infer<typeof ConfigSchema>;

export const CONFIG_FILES = [".ironmountain.yml", ".ironmountain.yaml", "ironmountain.config.json"];

export function parseConfig(raw: unknown): Config {
  return ConfigSchema.parse(raw ?? {});
}

export function loadConfig(repoRoot: string, explicitPath?: string): { config: Config; path?: string } {
  const candidates = explicitPath ? [explicitPath] : CONFIG_FILES.map((f) => join(repoRoot, f));
  for (const p of candidates) {
    if (!existsSync(p)) continue;
    const text = readFileSync(p, "utf8");
    const raw = p.endsWith(".json") ? JSON.parse(text) : parseYaml(text);
    return { config: parseConfig(raw), path: p };
  }
  if (explicitPath) throw new Error(`config file not found: ${explicitPath}`);
  return { config: parseConfig({}) };
}

/** Minimal glob matcher supporting **, * and ? (no external dependency). */
export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") {
          i++;
          re += "(?:.*/)?";
        } else re += ".*";
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

export function matchesAny(path: string, globs: string[]): boolean {
  return globs.some((g) => globToRegExp(g).test(path) || globToRegExp(g).test(path.split("/").pop()!));
}

export const DEFAULT_CONFIG_YAML = `# Iron Mountain - change-safety policy
# Docs: https://github.com/airostudio/ironmountain#configuration

# Block merges at or above this severity (critical | high | medium | low | info)
failOn: high
warnOn: medium

# Stricter gate applied automatically when the change was written by an AI agent
# (detected from commit trailers, branch names, bot authors, or declared by the caller).
ai:
  failOn: medium
  warnOn: low
  requireSuppressionReason: true

exclude:
  - "**/node_modules/**"
  - "**/dist/**"
  - "**/vendor/**"
  - "**/*.min.js"

# Per-rule overrides: "off", a severity, or { severity, paths, enabled }
rules: {}
#  web/plain-http: off
#  crypto/weak-hash: low

# Accepted risks. Every entry needs a reason.
ignore: []
#  - rule: injection/code-eval
#    path: "scripts/**"
#    reason: build-time only, inputs are constant

supplyChain:
  verifyRegistry: true   # flag hallucinated / brand-new packages (npm, PyPI)
  newPackageDays: 30

agent:
  enabled: true          # agentic review with Claude when ANTHROPIC_API_KEY is set
  model: claude-opus-5-5
  effort: high
  maxToolCalls: 40
  nonDismissible: [secrets, ai-integrity, supply-chain]
  # instructions: |
  #   Our API handlers must call requireTenant() before touching the DB.
`;
