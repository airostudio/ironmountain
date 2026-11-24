#!/usr/bin/env node
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { DEFAULT_CONFIG_YAML, loadConfig, type Config } from "./config.js";
import { GitHubClient } from "./github/api.js";
import { reviewPullRequest } from "./github/pr.js";
import { createWebhookServer } from "./github/server.js";
import { claudeCodeHookSettings, runEditHook, type HookPayload } from "./hooks/claude-code.js";
import { FORMATS, render, type Format } from "./report/index.js";
import { toSarif } from "./report/sarif.js";
import { ALL_RULES } from "./rules/index.js";
import { isInside } from "./repo.js";
import { reviewDiffText, reviewLocal, scanPaths } from "./run.js";
import { SEVERITIES, type Report, type Severity } from "./types.js";
import { VERSION } from "./version.js";

const HELP = `ironmountain ${VERSION} - agentic change-safety gate for AI-generated code

Usage:
  ironmountain review [options]          Review git changes (working tree by default)
  ironmountain scan [paths...]           Scan whole files / directories
  ironmountain pr <owner/repo#number>    Review a GitHub pull request (needs GITHUB_TOKEN)
  ironmountain ci                        Run inside GitHub Actions (PR comments, check, SARIF)
  ironmountain serve                     Run the GitHub App webhook server + dashboard
  ironmountain mcp                       Start the MCP server (stdio) for AI assistants
  ironmountain hook <name>               Agent/git hooks: claude-code | claude-stop | pre-commit
  ironmountain init [--claude] [--git-hooks] [--github-action]
  ironmountain rules                     List rules

Review options:
  --base <ref>          Diff against this ref (merge-base), e.g. origin/main
  --head <ref>          Head ref (default: working tree)
  --staged              Only staged changes
  --diff <file|->       Review a unified diff from a file or stdin
  --no-untracked        Ignore untracked files in working-tree reviews
  --format <fmt>        ${FORMATS.join(" | ")} (default terminal)
  --output, -o <file>   Write the report to a file
  --sarif <file>        Also write SARIF
  --fail-on <sev>       Override the blocking threshold (${SEVERITIES.join(" | ")})
  --agent / --no-agent  Force the Claude agentic reviewer on/off (default: on if credentials exist)
  --ai <name>           Declare the change as written by an AI tool (applies AI policy)
  --offline             Skip registry lookups
  --config <file>       Config file (default .ironmountain.yml)
  --quiet               Only print the verdict line

Exit codes: 0 pass/warn, 1 blocked, 2 error.
`;

function die(msg: string): never {
  process.stderr.write(`ironmountain: ${msg}\n`);
  process.exit(2);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function withFailOn(config: Config, failOn?: string): Config {
  if (!failOn) return config;
  if (!(SEVERITIES as readonly string[]).includes(failOn)) die(`invalid --fail-on ${failOn}`);
  return { ...config, failOn: failOn as Severity, ai: { ...config.ai, failOn: failOn as Severity } };
}

function emit(report: Report, v: Record<string, unknown>) {
  const format = ((v.format as string) ?? "terminal") as Format;
  if (!FORMATS.includes(format)) die(`unknown format ${format}`);
  const text = render(report, format);
  if (v.output) {
    mkdirSync(dirname(resolve(v.output as string)), { recursive: true });
    writeFileSync(v.output as string, text);
  }
  if (v.sarif) writeFileSync(v.sarif as string, JSON.stringify(toSarif(report), null, 2));
  if (v.quiet) process.stdout.write(`${report.verdict} risk=${report.riskScore} findings=${report.findings.filter((f) => !f.suppressed).length}\n`);
  else if (!v.output || format === "terminal") process.stdout.write(text + "\n");
  process.exitCode = report.verdict === "block" ? 1 : 0;
}

const REVIEW_OPTS = {
  base: { type: "string" },
  head: { type: "string" },
  staged: { type: "boolean" },
  diff: { type: "string" },
  "no-untracked": { type: "boolean" },
  format: { type: "string", short: "f" },
  output: { type: "string", short: "o" },
  sarif: { type: "string" },
  "fail-on": { type: "string" },
  agent: { type: "boolean" },
  "no-agent": { type: "boolean" },
  ai: { type: "string" },
  offline: { type: "boolean" },
  config: { type: "string" },
  quiet: { type: "boolean", short: "q" },
  verbose: { type: "boolean", short: "v" },
  cwd: { type: "string" },
} as const;

async function cmdReview(argv: string[]) {
  const { values: v } = parseArgs({ args: argv, options: REVIEW_OPTS, allowPositionals: false });
  const cwd = resolve(v.cwd ?? process.cwd());
  const config = withFailOn(loadConfig(cwd, v.config).config, v["fail-on"]);
  const agent = v["no-agent"] ? false : v.agent ? true : undefined;
  const common = {
    cwd,
    config,
    ...(agent !== undefined ? { agent } : {}),
    ...(v.offline ? { offline: true } : {}),
    ...(v.ai ? { declaredAgent: v.ai } : {}),
    ...(v.verbose ? { onEvent: (m: string) => process.stderr.write(`  · ${m}\n`) } : {}),
  };
  let report: Report;
  if (v.diff) {
    const text = v.diff === "-" ? await readStdin() : readFileSync(v.diff, "utf8");
    report = await reviewDiffText(text, { ...common, description: v.diff === "-" ? "stdin diff" : v.diff });
  } else {
    report = await reviewLocal({
      ...common,
      ...(v.base ? { base: v.base } : {}),
      ...(v.head ? { head: v.head } : {}),
      ...(v.staged ? { staged: true } : {}),
      ...(v["no-untracked"] ? { untracked: false } : {}),
    });
  }
  emit(report, v);
}

async function cmdScan(argv: string[]) {
  const { values: v, positionals } = parseArgs({ args: argv, options: REVIEW_OPTS, allowPositionals: true });
  const cwd = resolve(v.cwd ?? process.cwd());
  const config = withFailOn(loadConfig(cwd, v.config).config, v["fail-on"]);
  const report = await scanPaths(positionals, { cwd, config, offline: v.offline ?? true, ...(v.ai ? { declaredAgent: v.ai } : {}) });
  emit(report, v);
}

function parsePrRef(ref: string) {
  const m = /^([\w.-]+)\/([\w.-]+)#(\d+)$/.exec(ref) ?? /github\.com\/([\w.-]+)\/([\w.-]+)\/pull\/(\d+)/.exec(ref);
  if (!m) die(`expected owner/repo#number or a PR URL, got "${ref}"`);
  return { owner: m[1]!, repo: m[2]!, number: Number(m[3]) };
}

async function cmdPr(argv: string[]) {
  const { values: v, positionals } = parseArgs({ args: argv, options: { ...REVIEW_OPTS, post: { type: "boolean" } }, allowPositionals: true });
  if (!positionals[0]) die("usage: ironmountain pr <owner/repo#number> [--post]");
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (!token) die("GITHUB_TOKEN is required");
  const { owner, repo, number } = parsePrRef(positionals[0]);
  const agent = v["no-agent"] ? false : v.agent ? true : undefined;
  const report = await reviewPullRequest({
    gh: new GitHubClient(token),
    owner,
    repo,
    number,
    post: !!v.post,
    ...(agent !== undefined ? { agent } : {}),
    onEvent: (m) => v.verbose && process.stderr.write(`  · ${m}\n`),
  });
  emit(report, v);
}

/** GitHub Actions entrypoint: review the PR, publish comments/check/SARIF, and gate. */
async function cmdCi(argv: string[]) {
  const { values: v } = parseArgs({ args: argv, options: { ...REVIEW_OPTS, "no-post": { type: "boolean" } }, allowPositionals: false });
  const eventPath = process.env.GITHUB_EVENT_PATH;
  const event = eventPath && existsSync(eventPath) ? JSON.parse(readFileSync(eventPath, "utf8")) : {};
  const token = process.env.GITHUB_TOKEN;
  const agent = v["no-agent"] ? false : v.agent ? true : undefined;
  let report: Report;
  if (event.pull_request && token && process.env.GITHUB_REPOSITORY) {
    const [owner, repo] = process.env.GITHUB_REPOSITORY.split("/") as [string, string];
    report = await reviewPullRequest({
      gh: new GitHubClient(token),
      owner,
      repo,
      number: event.pull_request.number,
      post: !v["no-post"],
      ...(agent !== undefined ? { agent } : {}),
      onEvent: (m) => process.stderr.write(`  · ${m}\n`),
    });
  } else {
    const base = v.base ?? event.before ?? (process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : "HEAD~1");
    const cwd = resolve(v.cwd ?? process.cwd());
    report = await reviewLocal({
      cwd,
      config: withFailOn(loadConfig(cwd, v.config).config, v["fail-on"]),
      base: /^0+$/.test(base) ? "HEAD~1" : base,
      head: "HEAD",
      ...(agent !== undefined ? { agent } : {}),
    });
  }
  if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, render(report, "markdown") + "\n", { flag: "a" });
  if (process.env.GITHUB_OUTPUT) writeFileSync(process.env.GITHUB_OUTPUT, `verdict=${report.verdict}\nrisk-score=${report.riskScore}\nai-authored=${report.provenance.aiAuthored}\n`, { flag: "a" });
  emit(report, { ...v, sarif: v.sarif ?? "ironmountain.sarif" });
}

async function cmdHook(argv: string[]) {
  const name = argv[0];
  if (name === "claude-code" || name === "edit") {
    const raw = await readStdin();
    let payload: HookPayload = {};
    try {
      payload = JSON.parse(raw || "{}");
    } catch {
      die("hook expects a JSON payload on stdin");
    }
    const res = await runEditHook(payload, { agentName: argv[1] ?? "claude" });
    if (res.stderr) process.stderr.write(res.stderr + "\n");
    process.exit(res.exitCode);
  }
  if (name === "claude-stop") {
    // Runs when the agent declares it is done: review everything it changed.
    const raw = await readStdin();
    const payload = raw ? (JSON.parse(raw) as { stop_hook_active?: boolean; cwd?: string }) : {};
    if (payload.stop_hook_active) process.exit(0); // never loop forever
    const report = await reviewLocal({ cwd: payload.cwd ?? process.cwd(), agent: false, offline: false, declaredAgent: argv[1] ?? "claude" });
    if (report.verdict !== "block") process.exit(0);
    const active = report.findings.filter((f) => !f.suppressed);
    process.stderr.write(
      [`Iron Mountain blocked completion: ${report.gate.reason}. Fix these before finishing:`, ...active.slice(0, 20).map((f) => `- [${f.severity}] ${f.file}:${f.line} ${f.title}: ${f.message}`)].join("\n") + "\n",
    );
    process.exit(2);
  }
  if (name === "pre-commit" || name === "pre-push") {
    const report = await reviewLocal(name === "pre-commit" ? { staged: true, agent: false } : { base: "@{upstream}", head: "HEAD", agent: false });
    process.stdout.write(render(report, "terminal") + "\n");
    process.exit(report.verdict === "block" ? 1 : 0);
  }
  die("unknown hook. Use: claude-code | claude-stop | pre-commit | pre-push");
}

/**
 * How hooks should invoke this CLI. We never write `npx --yes ironmountain`: if the
 * package name were ever squatted, every hook run would execute someone else's code.
 */
function selfCommand(): { cmd: string; args: string[] } {
  const script = realpathSync(resolve(process.argv[1] ?? ""));
  // Project dev dependency: portable across machines, resolves to the locked local copy.
  if (isInside(join(realpathSync(process.cwd()), "node_modules"), script)) return { cmd: "npx", args: ["--no-install", "ironmountain"] };
  // Global install: the binary is on PATH (npx does not look at global packages).
  if (/[\\/]node_modules[\\/]ironmountain[\\/]/.test(script)) return { cmd: "ironmountain", args: [] };
  if (script.endsWith(".ts")) return { cmd: "npx", args: ["--no-install", "tsx", script] };
  return { cmd: "node", args: [script] };
}

const shellQuote = (s: string) => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replace(/'/g, "'\\''")}'`);

function cmdInit(argv: string[]) {
  const { values: v } = parseArgs({ args: argv, options: { claude: { type: "boolean" }, "git-hooks": { type: "boolean" }, "github-action": { type: "boolean" }, force: { type: "boolean" } } });
  const cwd = process.cwd();
  const sc = selfCommand();
  const self = [sc.cmd, ...sc.args].map(shellQuote).join(" ");
  const wrote: string[] = [];
  const write = (p: string, text: string, mode?: number) => {
    if (existsSync(p) && !v.force) {
      process.stderr.write(`skip ${p} (exists; use --force)\n`);
      return;
    }
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, text);
    if (mode) chmodSync(p, mode);
    wrote.push(p);
  };
  write(join(cwd, ".ironmountain.yml"), DEFAULT_CONFIG_YAML);

  if (v.claude) {
    const p = join(cwd, ".claude", "settings.json");
    const existing = existsSync(p) ? (JSON.parse(readFileSync(p, "utf8")) as Record<string, any>) : {};
    const add = claudeCodeHookSettings(self) as { hooks: Record<string, unknown[]> };
    existing.hooks ??= {};
    for (const [ev, entries] of Object.entries(add.hooks)) {
      const cur: unknown[] = existing.hooks[ev] ?? [];
      if (!JSON.stringify(cur).includes("ironmountain")) existing.hooks[ev] = [...cur, ...entries];
    }
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, JSON.stringify(existing, null, 2) + "\n");
    wrote.push(p);
    const mcp = join(cwd, ".mcp.json");
    const m = existsSync(mcp) ? (JSON.parse(readFileSync(mcp, "utf8")) as { mcpServers?: Record<string, unknown> }) : {};
    m.mcpServers = { ...(m.mcpServers ?? {}), ironmountain: { command: sc.cmd, args: [...sc.args, "mcp"] } };
    writeFileSync(mcp, JSON.stringify(m, null, 2) + "\n");
    wrote.push(mcp);
  }
  if (v["git-hooks"]) {
    const hookDir = join(cwd, ".git", "hooks");
    if (!existsSync(hookDir)) die("not a git repository");
    write(join(hookDir, "pre-commit"), `#!/bin/sh\nexec ${self} hook pre-commit\n`, 0o755);
    write(join(hookDir, "pre-push"), `#!/bin/sh\nexec ${self} hook pre-push\n`, 0o755);
  }
  if (v["github-action"]) {
    write(
      join(cwd, ".github", "workflows", "ironmountain.yml"),
      `name: Iron Mountain
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
permissions:
  contents: read
  pull-requests: write
  checks: write
  security-events: write
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      # Pin this to a release commit SHA once you cut one (Iron Mountain flags mutable refs).
      - uses: airostudio/ironmountain@main
        with:
          anthropic-api-key: \${{ secrets.ANTHROPIC_API_KEY }}
`,
    );
  }
  process.stdout.write(wrote.map((w) => `wrote ${w}`).join("\n") + "\n");
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "review":
      return cmdReview(rest);
    case "scan":
      return cmdScan(rest);
    case "pr":
      return cmdPr(rest);
    case "ci":
    case "github-action":
      return cmdCi(rest);
    case "hook":
      return cmdHook(rest);
    case "init":
      return cmdInit(rest);
    case "mcp": {
      const { startMcpServer } = await import("./mcp/server.js");
      return startMcpServer(process.cwd());
    }
    case "serve": {
      const { values: v } = parseArgs({ args: rest, options: { port: { type: "string", short: "p" }, "no-agent": { type: "boolean" } } });
      const secret = process.env.GITHUB_WEBHOOK_SECRET;
      if (!secret) die("GITHUB_WEBHOOK_SECRET is required");
      const pk = process.env.GITHUB_APP_PRIVATE_KEY ?? (process.env.GITHUB_APP_PRIVATE_KEY_PATH ? readFileSync(process.env.GITHUB_APP_PRIVATE_KEY_PATH, "utf8") : undefined);
      const server = createWebhookServer({
        webhookSecret: secret,
        ...(process.env.GITHUB_APP_ID ? { appId: process.env.GITHUB_APP_ID } : {}),
        ...(pk ? { privateKey: pk } : {}),
        ...(process.env.GITHUB_TOKEN ? { token: process.env.GITHUB_TOKEN } : {}),
        ...(v["no-agent"] ? { agent: false } : {}),
      });
      const port = Number(v.port ?? process.env.PORT ?? 3000);
      server.listen(port, () => console.log(`[ironmountain] listening on :${port} (POST /webhook, GET / dashboard)`));
      return;
    }
    case "rules":
      for (const r of ALL_RULES) process.stdout.write(`${r.id.padEnd(40)} ${r.severity.padEnd(9)} ${r.title}\n`);
      return;
    case "--version":
    case "-V":
      process.stdout.write(VERSION + "\n");
      return;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      process.stdout.write(HELP);
      return;
    default:
      die(`unknown command "${cmd}". Run "ironmountain --help".`);
  }
}

// Exit quietly when the reader goes away (e.g. `ironmountain rules | head`).
process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE") process.exit(process.exitCode ?? 0);
  throw err;
});

main().catch((err) => die((err as Error).stack ?? String(err)));
