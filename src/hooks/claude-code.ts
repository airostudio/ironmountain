import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { parseConfig } from "../config.js";
import { loadConfig } from "../config.js";
import { fileAsAdded } from "../diff.js";
import { review } from "../engine.js";
import { detectProvenance } from "../provenance.js";
import { isInside } from "../repo.js";
import type { DiffFile, Report } from "../types.js";
import { severityAtLeast } from "../types.js";

/**
 * Claude Code PostToolUse hook payload (subset).
 * https://code.claude.com/docs/en/hooks
 */
export interface HookPayload {
  hook_event_name?: string;
  tool_name?: string;
  cwd?: string;
  tool_input?: {
    file_path?: string;
    content?: string;
    new_string?: string;
    edits?: { new_string?: string }[];
    command?: string;
  };
}

export interface HookResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  report?: Report;
}

/**
 * Review the file an AI agent just wrote. Exit code 2 feeds the findings back to
 * the agent so it fixes them before moving on. Works with any agent that supports
 * command hooks with this JSON shape (Claude Code, and others via the same CLI).
 */
export async function runEditHook(payload: HookPayload, opts: { agentName?: string } = {}): Promise<HookResult> {
  const tool = payload.tool_name ?? "";
  const filePath = payload.tool_input?.file_path;
  if (!/^(Write|Edit|MultiEdit|NotebookEdit|str_replace_based_edit_tool|create_file|edit_file)$/.test(tool) || !filePath) {
    return { exitCode: 0, stdout: "", stderr: "" };
  }
  const cwd = resolve(payload.cwd ?? process.cwd());
  const abs = isAbsolute(filePath) ? filePath : resolve(cwd, filePath);
  const rel = isInside(cwd, abs) ? relative(cwd, abs) : abs;

  let config;
  try {
    config = loadConfig(cwd).config;
  } catch {
    config = parseConfig({});
  }

  let content: string;
  try {
    content = await readFile(abs, "utf8");
  } catch {
    content = payload.tool_input?.content ?? "";
  }

  // Only judge the lines this edit wrote when we can identify them; otherwise the whole file.
  const file: DiffFile = fileAsAdded(rel, content);
  const written = [payload.tool_input?.new_string, ...(payload.tool_input?.edits ?? []).map((e) => e.new_string)].filter((s): s is string => !!s);
  if (tool !== "Write" && written.length) {
    const writtenLines = new Set(written.flatMap((w) => w.split("\n").map((l) => l.trim())).filter(Boolean));
    file.added = file.added.filter((l) => writtenLines.has(l.content.trim()));
  }

  const report = await review({
    files: [file],
    provenance: detectProvenance({ declaredAgent: opts.agentName ?? "claude-code" }),
    config,
    offline: true,
    target: { description: `${tool} ${rel}` },
  });
  const blocking = report.findings.filter((f) => !f.suppressed && severityAtLeast(f.severity, report.gate.warnOn));
  if (!blocking.length) return { exitCode: 0, stdout: "", stderr: "", report };

  const lines = [
    `Iron Mountain found ${blocking.length} security issue(s) in ${rel}. Fix them before continuing:`,
    ...blocking.slice(0, 15).map((f) => `- [${f.severity}] ${f.title} (${f.ruleId}) at line ${f.line}: ${f.message}${f.remediation ? ` Fix: ${f.remediation}` : ""}`),
    `If a finding is a verified false positive, add a comment "ironmountain-ignore[<rule-id>]: <reason>" on that line.`,
  ];
  return { exitCode: 2, stdout: "", stderr: lines.join("\n"), report };
}

/**
 * The settings.json fragment that wires Iron Mountain into Claude Code.
 * `baseCommand` must invoke a locally installed CLI; never an auto-installing `npx --yes`.
 */
export function claudeCodeHookSettings(baseCommand: string): object {
  return {
    hooks: {
      PostToolUse: [{ matcher: "Write|Edit|MultiEdit", hooks: [{ type: "command", command: `${baseCommand} hook claude-code`, timeout: 30 }] }],
      Stop: [{ hooks: [{ type: "command", command: `${baseCommand} hook claude-stop`, timeout: 120 }] }],
    },
  };
}
