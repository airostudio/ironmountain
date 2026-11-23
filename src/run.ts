import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { agentCredentialsAvailable, createAgentReviewer } from "./agent/reviewer.js";
import { type Config, loadConfig, matchesAny } from "./config.js";
import { fileAsAdded, parseUnifiedDiff } from "./diff.js";
import { review } from "./engine.js";
import { detectProvenance, type ProvenanceInput } from "./provenance.js";
import { LocalRepo, type RepoReader } from "./repo.js";
import type { DiffFile, Report } from "./types.js";

export interface CommonOptions {
  cwd?: string;
  configPath?: string;
  config?: Config;
  /** true = require the agent, false = never, undefined = use it when credentials exist and config allows. */
  agent?: boolean;
  offline?: boolean;
  declaredAgent?: string;
  onEvent?: (msg: string) => void;
}

function resolveAgent(opts: CommonOptions, config: Config, repo: RepoReader, notices: string[]) {
  const wanted = opts.agent ?? config.agent.enabled;
  if (!wanted) return undefined;
  if (!agentCredentialsAvailable()) {
    if (opts.agent === true) notices.push("Agentic review requested but no Anthropic credentials were found (set ANTHROPIC_API_KEY or run `ant auth login`).");
    return undefined;
  }
  return createAgentReviewer({ repo, ...(opts.onEvent ? { onEvent: opts.onEvent } : {}) });
}

async function finish(files: DiffFile[], provInput: ProvenanceInput, target: Report["target"], repo: RepoReader, opts: CommonOptions, config: Config) {
  const notices: string[] = [];
  const agent = resolveAgent(opts, config, repo, notices);
  const report = await review({
    files,
    provenance: detectProvenance({ ...provInput, ...(opts.declaredAgent ? { declaredAgent: opts.declaredAgent } : {}) }),
    config,
    target,
    ...(opts.offline ? { offline: true } : {}),
    ...(agent ? { agent } : {}),
  });
  report.notices.unshift(...notices);
  return report;
}

export interface LocalReviewOptions extends CommonOptions {
  base?: string;
  head?: string;
  staged?: boolean;
  /** Include untracked (new, never-added) files. Default true for working-tree reviews. */
  untracked?: boolean;
}

/** Review changes in a local git repository (working tree, staged, or a commit range). */
export async function reviewLocal(opts: LocalReviewOptions = {}): Promise<Report> {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const repo = new LocalRepo(cwd);
  if (!(await repo.isRepo())) throw new Error(`${cwd} is not a git repository (use \`ironmountain scan <paths>\` for plain directories)`);
  const config = opts.config ?? loadConfig(cwd, opts.configPath).config;
  const diffText = await repo.diff(opts);
  const files = parseUnifiedDiff(diffText);

  const workingTree = !opts.staged && !opts.head;
  if (workingTree && opts.untracked !== false) {
    for (const p of await repo.untrackedFiles()) {
      if (matchesAny(p, config.exclude)) continue;
      const text = await repo.readFile(p);
      if (text !== null) files.push(fileAsAdded(p, text));
    }
  }

  const range = opts.base ? `${opts.base}..${opts.head ?? "HEAD"}` : undefined;
  const { messages, authors } = await repo.commitInfo(range);
  const branch = await repo.branch();
  const description = opts.staged ? "staged changes" : opts.base ? `${opts.base}...${opts.head ?? "working tree"}` : "working tree changes";
  return finish(
    files,
    { commitMessages: messages, authors, ...(branch ? { branch } : {}) },
    { ...(opts.base ? { base: opts.base } : {}), ...(opts.head ? { head: opts.head } : {}), description },
    repo,
    opts,
    config,
  );
}

/** Review a unified diff supplied as text (stdin, MCP, webhooks). */
export async function reviewDiffText(diff: string, opts: CommonOptions & { provenance?: ProvenanceInput; description?: string } = {}): Promise<Report> {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const config = opts.config ?? loadConfig(cwd, opts.configPath).config;
  return finish(parseUnifiedDiff(diff), opts.provenance ?? {}, { description: opts.description ?? "supplied diff" }, new LocalRepo(cwd), opts, config);
}

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "vendor", ".venv", "venv", "__pycache__", ".next", "target", "coverage"]);

async function walk(root: string, dir: string, out: string[], limit: number) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (out.length >= limit) return;
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) await walk(root, full, out, limit);
    } else if (e.isFile()) out.push(relative(root, full));
  }
}

/** Scan whole files (not a diff) - useful for auditing an existing codebase or generated snippets. */
export async function scanPaths(paths: string[], opts: CommonOptions & { maxFiles?: number } = {}): Promise<Report> {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const config = opts.config ?? loadConfig(cwd, opts.configPath).config;
  const rels: string[] = [];
  for (const p of paths.length ? paths : ["."]) {
    const full = resolve(cwd, p);
    const s = await stat(full);
    if (s.isDirectory()) await walk(cwd, full, rels, opts.maxFiles ?? 5000);
    else rels.push(relative(cwd, full));
  }
  const files: DiffFile[] = [];
  for (const r of rels) {
    if (matchesAny(r, config.exclude)) continue;
    const s = await stat(join(cwd, r));
    if (s.size > 1_000_000) continue;
    const text = await readFile(join(cwd, r), "utf8");
    files.push(fileAsAdded(r, text));
  }
  return finish(files, {}, { description: `scan of ${paths.join(", ") || "."}` }, new LocalRepo(cwd), { ...opts, agent: opts.agent ?? false }, config);
}

/** Scan a single in-memory snippet (used by the MCP server and editor hooks). */
export async function scanSnippet(filename: string, content: string, opts: CommonOptions = {}): Promise<Report> {
  const cwd = resolve(opts.cwd ?? process.cwd());
  const config = opts.config ?? loadConfig(cwd, opts.configPath).config;
  return finish([fileAsAdded(filename, content)], {}, { description: `snippet ${filename}` }, new LocalRepo(cwd), { ...opts, agent: opts.agent ?? false }, config);
}
