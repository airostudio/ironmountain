import { createSign } from "node:crypto";
import { COMMENT_MARKER, findingBody } from "../report/markdown.js";
import { toMarkdown } from "../report/markdown.js";
import type { DiffFile, Finding, Report } from "../types.js";

export class GitHubClient {
  constructor(
    private token: string,
    private apiUrl = process.env.GITHUB_API_URL ?? "https://api.github.com",
  ) {}

  async request<T = unknown>(method: string, path: string, body?: unknown, accept = "application/vnd.github+json"): Promise<T> {
    const res = await fetch(`${this.apiUrl}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.token}`,
        accept,
        "x-github-api-version": "2022-11-28",
        "user-agent": "ironmountain",
        ...(body ? { "content-type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`GitHub ${method} ${path} -> ${res.status}: ${text.slice(0, 300)}`);
    }
    if (accept.includes("diff")) return (await res.text()) as T;
    return res.status === 204 ? (undefined as T) : ((await res.json()) as T);
  }

  getPullDiff(owner: string, repo: string, number: number) {
    return this.request<string>("GET", `/repos/${owner}/${repo}/pulls/${number}`, undefined, "application/vnd.github.v3.diff");
  }

  getPull(owner: string, repo: string, number: number) {
    return this.request<PullRequest>("GET", `/repos/${owner}/${repo}/pulls/${number}`);
  }

  async listPullCommits(owner: string, repo: string, number: number) {
    return this.request<{ commit: { message: string; author: { name: string; email: string } }; author: { login: string } | null }[]>(
      "GET",
      `/repos/${owner}/${repo}/pulls/${number}/commits?per_page=100`,
    );
  }

  async getFile(owner: string, repo: string, path: string, ref: string): Promise<string | null> {
    try {
      const data = await this.request<{ content?: string; encoding?: string; type: string }>(
        "GET",
        `/repos/${owner}/${repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(ref)}`,
      );
      if (data.type !== "file" || !data.content) return null;
      return Buffer.from(data.content, (data.encoding as BufferEncoding) ?? "base64").toString("utf8");
    } catch {
      return null;
    }
  }

  async listDir(owner: string, repo: string, path: string, ref: string): Promise<string[]> {
    try {
      const data = await this.request<{ name: string; type: string }[]>("GET", `/repos/${owner}/${repo}/contents/${path === "." ? "" : path}?ref=${encodeURIComponent(ref)}`);
      return Array.isArray(data) ? data.map((e) => (e.type === "dir" ? e.name + "/" : e.name)) : [];
    } catch {
      return [];
    }
  }

  /** Create or update the single sticky summary comment. */
  async upsertSummaryComment(owner: string, repo: string, number: number, body: string) {
    const comments = await this.request<{ id: number; body: string }[]>("GET", `/repos/${owner}/${repo}/issues/${number}/comments?per_page=100`);
    const existing = comments.find((c) => c.body?.includes(COMMENT_MARKER));
    if (existing) return this.request("PATCH", `/repos/${owner}/${repo}/issues/comments/${existing.id}`, { body });
    return this.request("POST", `/repos/${owner}/${repo}/issues/${number}/comments`, { body });
  }

  /** Post a review with inline comments on the changed lines. */
  async postReview(owner: string, repo: string, number: number, commitId: string, report: Report, files: DiffFile[], maxComments = 30) {
    const existing = await this.request<{ body: string }[]>("GET", `/repos/${owner}/${repo}/pulls/${number}/comments?per_page=100`).catch(() => []);
    const already = new Set(existing.map((c) => /ironmountain:fp=([0-9a-f]+)/.exec(c.body)?.[1]).filter(Boolean));
    const comments = inlineComments(report.findings, files)
      .filter((c) => !already.has(c.fingerprint))
      .slice(0, maxComments)
      .map(({ fingerprint: _f, ...c }) => c);
    if (!comments.length && report.verdict !== "block") return;
    await this.request("POST", `/repos/${owner}/${repo}/pulls/${number}/reviews`, {
      commit_id: commitId,
      event: report.verdict === "block" ? "REQUEST_CHANGES" : "COMMENT",
      body:
        report.verdict === "block"
          ? `⛔ Iron Mountain blocked this change: ${report.gate.reason}. See the summary comment for details.`
          : `Iron Mountain left ${comments.length} comment(s).`,
      comments,
    });
  }

  /** Create a check run so the verdict can be a required status check. */
  async createCheckRun(owner: string, repo: string, headSha: string, report: Report) {
    const active = report.findings.filter((f) => !f.suppressed);
    const annotations = active.slice(0, 50).map((f) => ({
      path: f.file,
      start_line: Math.max(1, f.line),
      end_line: Math.max(1, f.line),
      annotation_level: f.severity === "critical" || f.severity === "high" ? "failure" : f.severity === "medium" ? "warning" : "notice",
      title: `${f.title} (${f.ruleId})`.slice(0, 255),
      message: f.message.slice(0, 64_000),
    }));
    return this.request("POST", `/repos/${owner}/${repo}/check-runs`, {
      name: "Iron Mountain",
      head_sha: headSha,
      status: "completed",
      conclusion: report.verdict === "block" ? "failure" : report.verdict === "warn" ? "neutral" : "success",
      output: {
        title: `${report.verdict.toUpperCase()} · risk ${report.riskScore}/100 · ${active.length} finding(s)`,
        summary: toMarkdown(report).slice(0, 65_000),
        annotations,
      },
    });
  }
}

export interface PullRequest {
  number: number;
  title: string;
  body: string | null;
  head: { sha: string; ref: string; repo: { full_name: string } | null };
  base: { sha: string; ref: string };
  user: { login: string };
}

/** Map findings to review comments; only lines present in the diff can be commented on. */
export function inlineComments(findings: Finding[], files: DiffFile[]) {
  const commentable = new Map(files.map((f) => [f.path, new Set(f.added.map((l) => l.line))]));
  return findings
    .filter((f) => !f.suppressed && commentable.get(f.file)?.has(f.line) && f.severity !== "info")
    .map((f) => ({
      path: f.file,
      line: f.line,
      side: "RIGHT" as const,
      body: `${findingBody(f)}\n<!-- ironmountain:fp=${f.fingerprint} -->`,
      fingerprint: f.fingerprint,
    }));
}

// ---------- GitHub App authentication ----------

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

export function appJwt(appId: string, privateKeyPem: string, now = Math.floor(Date.now() / 1000)): string {
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId }));
  const signer = createSign("RSA-SHA256");
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${b64url(signer.sign(privateKeyPem))}`;
}

export async function installationToken(appId: string, privateKeyPem: string, installationId: number, apiUrl = "https://api.github.com"): Promise<string> {
  const res = await fetch(`${apiUrl}/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    headers: { authorization: `Bearer ${appJwt(appId, privateKeyPem)}`, accept: "application/vnd.github+json", "user-agent": "ironmountain" },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`installation token request failed: ${res.status}`);
  return ((await res.json()) as { token: string }).token;
}
