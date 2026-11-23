import { execFile } from "node:child_process";
import { readFile, readdir, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

/** Read-only view of a repository, used by the agentic reviewer's tools. */
export interface RepoReader {
  readFile(path: string): Promise<string | null>;
  listDir(path: string): Promise<string[]>;
  search(pattern: string, pathGlob?: string): Promise<string[]>;
}

export async function git(cwd: string, args: string[], maxBuffer = 64 * 1024 * 1024): Promise<string> {
  const { stdout } = await run("git", args, { cwd, maxBuffer, encoding: "utf8" });
  return stdout;
}

const MAX_FILE_BYTES = 400_000;

export function isInside(root: string, p: string): boolean {
  const rel = relative(root, p);
  return rel === "" || (rel !== ".." && !rel.startsWith(".." + sep) && !isAbsolute(rel));
}

export class LocalRepo implements RepoReader {
  readonly root: string;
  constructor(root: string) {
    this.root = resolve(root);
  }

  /** Resolve a model- or user-supplied path and refuse anything outside the repo root. */
  async safePath(p: string): Promise<string | null> {
    if (p.includes("\u0000")) return null;
    const target = resolve(this.root, p);
    if (!isInside(this.root, target)) return null;
    if (/(^|[/\\])\.git([/\\]|$)/.test(relative(this.root, target))) return null;
    try {
      // Canonicalize to defeat symlinks that point outside the repository.
      const [real, realRoot] = await Promise.all([realpath(target), realpath(this.root)]);
      return isInside(realRoot, real) ? real : null;
    } catch {
      return null;
    }
  }

  async readFile(p: string): Promise<string | null> {
    const full = await this.safePath(p);
    if (!full) return null;
    const s = await stat(full).catch(() => null);
    if (!s?.isFile()) return null;
    const buf = await readFile(full);
    const text = buf.subarray(0, MAX_FILE_BYTES).toString("utf8");
    return buf.length > MAX_FILE_BYTES ? text + `\n…[truncated ${buf.length - MAX_FILE_BYTES} bytes]` : text;
  }

  async listDir(p: string): Promise<string[]> {
    const full = await this.safePath(p || ".");
    if (!full) return [];
    const entries = await readdir(full, { withFileTypes: true }).catch(() => []);
    return entries.filter((e) => e.name !== ".git").map((e) => (e.isDirectory() ? e.name + "/" : e.name)).sort();
  }

  async search(pattern: string, pathGlob?: string): Promise<string[]> {
    const args = ["grep", "-n", "-I", "-E", "--max-count=20", "-e", pattern];
    if (pathGlob) args.push("--", pathGlob);
    try {
      const out = await git(this.root, args, 4 * 1024 * 1024);
      return out.split("\n").filter(Boolean).slice(0, 200).map((l) => (l.length > 300 ? l.slice(0, 300) + "…" : l));
    } catch (err) {
      const e = err as { code?: number };
      if (e.code === 1) return []; // no matches
      throw err;
    }
  }

  async isRepo(): Promise<boolean> {
    try {
      await git(this.root, ["rev-parse", "--git-dir"]);
      return true;
    } catch {
      return false;
    }
  }

  async diff(opts: { base?: string; head?: string; staged?: boolean }): Promise<string> {
    const args = ["diff", "--no-color", "--no-ext-diff", "-U3", "--find-renames"];
    if (opts.staged) args.push("--cached");
    else if (opts.base && opts.head) args.push(`${opts.base}...${opts.head}`);
    else if (opts.base) args.push(opts.base);
    return git(this.root, args);
  }

  /** Untracked files are invisible to `git diff`; include them so new files written by agents are reviewed. */
  async untrackedFiles(): Promise<string[]> {
    const out = await git(this.root, ["ls-files", "--others", "--exclude-standard", "-z"]);
    return out.split("\u0000").filter(Boolean);
  }

  async commitInfo(range?: string): Promise<{ messages: string[]; authors: string[] }> {
    try {
      const out = await git(this.root, ["log", "--format=%an <%ae>%x1f%B%x1e", "-n", "200", ...(range ? [range] : ["-n", "1", "HEAD"])]);
      const entries = out.split("\u001e").map((s) => s.trim()).filter(Boolean);
      return {
        authors: entries.map((e) => e.split("\u001f")[0]!.trim()),
        messages: entries.map((e) => e.split("\u001f")[1] ?? ""),
      };
    } catch {
      return { messages: [], authors: [] };
    }
  }

  async branch(): Promise<string | undefined> {
    try {
      return (await git(this.root, ["rev-parse", "--abbrev-ref", "HEAD"])).trim();
    } catch {
      return undefined;
    }
  }
}
