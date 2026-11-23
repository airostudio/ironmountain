import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { toHtml } from "../report/html.js";
import type { Report } from "../types.js";
import { GitHubClient, installationToken } from "./api.js";
import { reviewPullRequest } from "./pr.js";

export function verifySignature(secret: string, body: Buffer, header: string | undefined): boolean {
  if (!header?.startsWith("sha256=")) return false;
  const expected = Buffer.from("sha256=" + createHmac("sha256", secret).update(body).digest("hex"));
  const given = Buffer.from(header);
  return expected.length === given.length && timingSafeEqual(expected, given);
}

async function readBody(req: IncomingMessage, limit = 25 * 1024 * 1024): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new Error("payload too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export interface ServerOptions {
  webhookSecret: string;
  /** GitHub App credentials, or a static token for single-repo setups. */
  appId?: string;
  privateKey?: string;
  token?: string;
  agent?: boolean;
  log?: (m: string) => void;
}

interface Event {
  action?: string;
  installation?: { id: number };
  repository?: { name: string; owner: { login: string } };
  pull_request?: { number: number; draft?: boolean };
  issue?: { number: number; pull_request?: unknown };
  comment?: { body: string; author_association?: string };
}

/** Webhook server for running Iron Mountain as a GitHub App (CodeRabbit-style PR bot). */
export function createWebhookServer(opts: ServerOptions): Server {
  const log = opts.log ?? ((m: string) => console.log(`[ironmountain] ${m}`));
  const recent: { at: string; target: string; report: Report }[] = [];
  const inflight = new Map<string, Promise<void>>();

  const clientFor = async (installationId?: number) => {
    if (opts.appId && opts.privateKey && installationId) return new GitHubClient(await installationToken(opts.appId, opts.privateKey, installationId));
    if (opts.token) return new GitHubClient(opts.token);
    throw new Error("no GitHub credentials configured");
  };

  const schedule = (ev: Event, number: number) => {
    const owner = ev.repository!.owner.login;
    const repo = ev.repository!.name;
    const key = `${owner}/${repo}#${number}`;
    // Serialize reviews per PR so rapid pushes don't race each other.
    const prev = inflight.get(key) ?? Promise.resolve();
    const next = prev
      .then(async () => {
        const gh = await clientFor(ev.installation?.id);
        log(`reviewing ${key}`);
        const report = await reviewPullRequest({ gh, owner, repo, number, ...(opts.agent !== undefined ? { agent: opts.agent } : {}), onEvent: (m) => log(`${key}: ${m}`) });
        recent.unshift({ at: new Date().toISOString(), target: key, report });
        recent.length = Math.min(recent.length, 50);
        log(`${key}: ${report.verdict} (risk ${report.riskScore})`);
      })
      .catch((err) => log(`${key}: review failed: ${(err as Error).message}`))
      .finally(() => {
        if (inflight.get(key) === next) inflight.delete(key);
      });
    inflight.set(key, next);
  };

  return createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/healthz") {
        res.writeHead(200, { "content-type": "text/plain" }).end("ok");
        return;
      }
      if (req.method === "GET" && (req.url === "/" || req.url?.startsWith("/reviews/"))) {
        const idx = req.url === "/" ? -1 : Number(req.url.split("/")[2]);
        if (idx >= 0 && recent[idx]) {
          res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'" }).end(toHtml(recent[idx]!.report));
          return;
        }
        const rows = recent
          .map((r, i) => `<tr><td>${r.at}</td><td><a href="/reviews/${i}">${r.target.replace(/[<>&"]/g, "")}</a></td><td>${r.report.verdict}</td><td>${r.report.riskScore}</td><td>${r.report.findings.filter((f) => !f.suppressed).length}</td><td>${r.report.provenance.agents.join(", ") || "human"}</td></tr>`)
          .join("");
        res
          .writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'" })
          .end(
            `<!doctype html><meta charset="utf-8"><title>Iron Mountain</title><style>body{font:15px system-ui;margin:24px}table{border-collapse:collapse}td,th{border-bottom:1px solid #ddd;padding:6px 12px;text-align:left}</style><h1>🏔️ Iron Mountain</h1><p>Recent reviews</p><table><tr><th>When</th><th>PR</th><th>Verdict</th><th>Risk</th><th>Findings</th><th>Author agent</th></tr>${rows || '<tr><td colspan="6">No reviews yet.</td></tr>'}</table>`,
          );
        return;
      }
      if (req.method !== "POST" || req.url !== "/webhook") {
        res.writeHead(404).end();
        return;
      }
      const body = await readBody(req);
      if (!verifySignature(opts.webhookSecret, body, req.headers["x-hub-signature-256"] as string | undefined)) {
        res.writeHead(401).end("bad signature");
        return;
      }
      const name = req.headers["x-github-event"];
      const ev = JSON.parse(body.toString("utf8")) as Event;
      res.writeHead(202).end("accepted");

      if (name === "pull_request" && ev.pull_request && ["opened", "synchronize", "reopened", "ready_for_review"].includes(ev.action ?? "")) {
        if (ev.pull_request.draft && ev.action !== "ready_for_review") return;
        schedule(ev, ev.pull_request.number);
      } else if (name === "issue_comment" && ev.action === "created" && ev.issue?.pull_request && /^\s*\/ironmountain\s+review\b/m.test(ev.comment?.body ?? "")) {
        // Only collaborators can trigger re-reviews (they spend API credits).
        if (!["OWNER", "MEMBER", "COLLABORATOR"].includes(ev.comment?.author_association ?? "")) return;
        schedule(ev, ev.issue.number);
      }
    } catch (err) {
      log(`webhook error: ${(err as Error).message}`);
      if (!res.headersSent) res.writeHead(400).end("bad request");
    }
  });
}
