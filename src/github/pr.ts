import { parseConfig, type Config } from "../config.js";
import { parse as parseYaml } from "yaml";
import { createAgentReviewer, agentCredentialsAvailable } from "../agent/reviewer.js";
import { parseUnifiedDiff } from "../diff.js";
import { review } from "../engine.js";
import { detectProvenance } from "../provenance.js";
import { toMarkdown } from "../report/markdown.js";
import type { RepoReader } from "../repo.js";
import type { Report } from "../types.js";
import { GitHubClient } from "./api.js";

/** Read-only repository view backed by the GitHub contents API at the PR head. */
export class GitHubRepoReader implements RepoReader {
  constructor(
    private gh: GitHubClient,
    private owner: string,
    private repo: string,
    private ref: string,
    private changedFiles: Map<string, string[]>,
  ) {}
  readFile(path: string) {
    if (path.includes("..")) return Promise.resolve(null);
    return this.gh.getFile(this.owner, this.repo, path.replace(/^\.?\//, ""), this.ref);
  }
  listDir(path: string) {
    if (path.includes("..")) return Promise.resolve([]);
    return this.gh.listDir(this.owner, this.repo, path.replace(/^\.?\//, ""), this.ref);
  }
  async search(pattern: string): Promise<string[]> {
    // The code-search API does not support regex or arbitrary refs; search the changed files instead.
    const re = new RegExp(pattern);
    const out: string[] = [];
    for (const [path] of this.changedFiles) {
      const text = await this.readFile(path);
      text?.split("\n").forEach((l, i) => {
        if (re.test(l) && out.length < 200) out.push(`${path}:${i + 1}:${l.slice(0, 300)}`);
      });
    }
    return out.length ? out : [`(search limited to changed files in GitHub App mode; no matches)`];
  }
}

export interface PrReviewOptions {
  gh: GitHubClient;
  owner: string;
  repo: string;
  number: number;
  agent?: boolean;
  post?: boolean;
  onEvent?: (m: string) => void;
}

/** Review a pull request end-to-end and (optionally) publish results back to GitHub. */
export async function reviewPullRequest(o: PrReviewOptions): Promise<Report> {
  const { gh, owner, repo, number } = o;
  const pr = await gh.getPull(owner, repo, number);
  const [diff, commits] = await Promise.all([gh.getPullDiff(owner, repo, number), gh.listPullCommits(owner, repo, number).catch(() => [])]);
  const files = parseUnifiedDiff(diff);

  // Config comes from the BASE branch so a PR cannot weaken its own gate.
  let config: Config = parseConfig({});
  const cfgText = (await gh.getFile(owner, repo, ".ironmountain.yml", pr.base.sha)) ?? (await gh.getFile(owner, repo, ".ironmountain.yaml", pr.base.sha));
  if (cfgText) config = parseConfig(parseYaml(cfgText));

  const provenance = detectProvenance({
    commitMessages: commits.map((c) => c.commit.message),
    authors: [pr.user.login, ...commits.map((c) => c.author?.login ?? `${c.commit.author.name} <${c.commit.author.email}>`)],
    branch: pr.head.ref,
    prBody: pr.body ?? "",
    prTitle: pr.title,
  });

  const wantAgent = (o.agent ?? config.agent.enabled) && agentCredentialsAvailable();
  const reader = new GitHubRepoReader(gh, owner, repo, pr.head.sha, new Map(files.map((f) => [f.path, []])));
  const report = await review({
    files,
    provenance,
    config,
    target: { base: pr.base.sha, head: pr.head.sha, description: `${owner}/${repo}#${number}` },
    ...(wantAgent ? { agent: createAgentReviewer({ repo: reader, ...(o.onEvent ? { onEvent: o.onEvent } : {}) }) } : {}),
  });

  if (o.post !== false) {
    // Posting can fail on fork PRs (read-only token); the verdict and exit code still stand.
    await gh.upsertSummaryComment(owner, repo, number, toMarkdown(report)).catch((e) => o.onEvent?.(`summary comment failed: ${e.message}`));
    await gh.postReview(owner, repo, number, pr.head.sha, report, files).catch((e) => o.onEvent?.(`review comments failed: ${e.message}`));
    await gh.createCheckRun(owner, repo, pr.head.sha, report).catch((e) => o.onEvent?.(`check run failed (needs checks:write): ${e.message}`));
  }
  return report;
}
