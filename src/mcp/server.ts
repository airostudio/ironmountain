import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { ALL_RULES } from "../rules/index.js";
import { toMarkdown } from "../report/markdown.js";
import { reviewDiffText, reviewLocal, scanSnippet } from "../run.js";
import type { Report } from "../types.js";
import { VERSION } from "../version.js";

function result(report: Report) {
  const compact = {
    verdict: report.verdict,
    riskScore: report.riskScore,
    gate: report.gate,
    aiAuthored: report.provenance.aiAuthored,
    findings: report.findings
      .filter((f) => !f.suppressed)
      .map((f) => ({ ruleId: f.ruleId, severity: f.severity, file: f.file, line: f.line, title: f.title, message: f.message, remediation: f.remediation })),
    notices: report.notices,
  };
  return {
    content: [
      { type: "text" as const, text: toMarkdown(report) },
      { type: "text" as const, text: JSON.stringify(compact, null, 2) },
    ],
    structuredContent: compact,
  };
}

const agentParam = z.string().optional().describe("Name of the AI tool that wrote the code (e.g. 'claude', 'cursor', 'codex'). Applies the stricter AI policy.");

/**
 * MCP server so any MCP-capable assistant (Claude Code, Claude Desktop, Cursor,
 * Windsurf, VS Code Copilot, Codex CLI, Gemini CLI, ...) can gate its own output.
 */
export function createMcpServer(cwd: string): McpServer {
  const server = new McpServer({ name: "ironmountain", version: VERSION });

  server.registerTool(
    "review_changes",
    {
      title: "Review uncommitted / branch changes",
      description:
        "Security-review the current git changes in the workspace (working tree by default, or a base ref). Call this before you tell the user a coding task is done, and fix every finding at or above the reported gate.",
      inputSchema: {
        base: z.string().optional().describe("Base ref to diff against, e.g. 'main' or 'origin/main'. Omit for uncommitted changes."),
        staged: z.boolean().optional().describe("Review only staged changes"),
        path: z.string().optional().describe("Repository path (defaults to the server's working directory)"),
        deep: z.boolean().optional().describe("Also run the Claude agentic reviewer (slower; needs Anthropic credentials on the server)"),
        agent: agentParam,
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ base, staged, path, deep, agent }) =>
      result(await reviewLocal({ cwd: path ?? cwd, ...(base ? { base } : {}), ...(staged ? { staged } : {}), declaredAgent: agent ?? "mcp-client", agent: deep === true })),
  );

  server.registerTool(
    "review_diff",
    {
      title: "Review a unified diff",
      description: "Security-review a unified diff (git diff format) and return findings plus a block/warn/pass verdict.",
      inputSchema: { diff: z.string().min(1).describe("Unified diff text"), agent: agentParam },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ diff, agent }) => result(await reviewDiffText(diff, { cwd, provenance: agent ? { declaredAgent: agent } : {}, agent: false })),
  );

  server.registerTool(
    "scan_code",
    {
      title: "Scan a code snippet",
      description: "Scan source code you are about to write or have just generated. Pass the intended filename so language-specific rules apply.",
      inputSchema: {
        filename: z.string().describe("e.g. 'src/api/users.ts' or 'requirements.txt'"),
        content: z.string().describe("Full file content or snippet"),
        agent: agentParam,
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ filename, content, agent }) => result(await scanSnippet(filename, content, { cwd, offline: true, declaredAgent: agent ?? "mcp-client" })),
  );

  server.registerTool(
    "list_rules",
    {
      title: "List Iron Mountain rules",
      description: "List the security rules Iron Mountain enforces, with severities and remediation guidance.",
      inputSchema: { category: z.string().optional() },
      annotations: { readOnlyHint: true },
    },
    async ({ category }) => ({
      content: [
        {
          type: "text" as const,
          text: ALL_RULES.filter((r) => !category || r.category === category)
            .map((r) => `${r.id} [${r.severity}] ${r.title}\n  ${r.remediation}`)
            .join("\n"),
        },
      ],
    }),
  );

  return server;
}

export async function startMcpServer(cwd: string): Promise<void> {
  const server = createMcpServer(cwd);
  await server.connect(new StdioServerTransport());
}
