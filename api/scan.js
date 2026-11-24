// Vercel function: POST /api/scan - runs the Iron Mountain static engine on a pasted snippet.
// Static rules only: no LLM calls, no registry lookups, no secrets. Safe to expose publicly.
import { parseConfig } from "../dist/config.js";
import { fileAsAdded } from "../dist/diff.js";
import { review } from "../dist/engine.js";
import { detectProvenance, HUMAN_PROVENANCE } from "../dist/provenance.js";

const MAX_BYTES = 200_000;
const config = parseConfig({});
const json = (status, body) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });

export async function POST(request) {
  const len = Number(request.headers.get("content-length") ?? 0);
  if (len > MAX_BYTES) return json(413, { error: `Snippet too large (limit ${MAX_BYTES / 1000} kB).` });

  let body;
  try {
    const text = await request.text();
    if (text.length > MAX_BYTES) return json(413, { error: `Snippet too large (limit ${MAX_BYTES / 1000} kB).` });
    body = JSON.parse(text);
  } catch {
    return json(400, { error: "Expected a JSON body." });
  }

  const content = typeof body?.content === "string" ? body.content : "";
  const filename = typeof body?.filename === "string" && /^[\w.\-/ ]{1,200}$/.test(body.filename) ? body.filename.replace(/^\/+/, "") : "snippet.js";
  if (!content.trim()) return json(400, { error: "Paste some code to scan." });

  const provenance = body?.aiAuthored ? detectProvenance({ declaredAgent: String(body.agent ?? "ai").slice(0, 40) }) : HUMAN_PROVENANCE;
  const report = await review({ files: [fileAsAdded(filename, content)], provenance, config, offline: true, target: { description: filename } });

  return json(200, {
    verdict: report.verdict,
    riskScore: report.riskScore,
    gate: report.gate,
    aiAuthored: report.provenance.aiAuthored,
    durationMs: report.stats.durationMs,
    rulesRun: report.stats.rulesRun,
    findings: report.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      category: f.category,
      line: f.line,
      message: f.message,
      remediation: f.remediation,
      snippet: f.snippet,
      cwe: f.cwe ?? [],
    })),
  });
}

export function GET() {
  return json(405, { error: "POST a JSON body: { filename, content, aiAuthored }" });
}
