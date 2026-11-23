import { describe, expect, it } from "vitest";
import { globToRegExp, parseConfig } from "../src/config.js";
import { fileAsAdded, parseUnifiedDiff } from "../src/diff.js";
import { review, type AgentHook } from "../src/engine.js";
import { detectProvenance } from "../src/provenance.js";
import { toMarkdown } from "../src/report/markdown.js";
import { toSarif } from "../src/report/sarif.js";
import { toHtml } from "../src/report/html.js";
import { fake } from "./helpers.js";

const AI = detectProvenance({ commitMessages: ["feat: add login\n\nCo-Authored-By: Claude <noreply@anthropic.com>"] });

describe("diff parser", () => {
  it("tracks new-file line numbers across hunks, renames and deletions", () => {
    const files = parseUnifiedDiff(`diff --git a/src/a.ts b/src/a.ts
index 111..222 100644
--- a/src/a.ts
+++ b/src/a.ts
@@ -1,4 +1,5 @@
 line1
-old2
+new2
+new3
 line3
 line4
@@ -20,2 +21,3 @@ function f() {
 ctx
+added22
 ctx
diff --git a/old.txt b/new.txt
similarity index 90%
rename from old.txt
rename to new.txt
diff --git a/gone.js b/gone.js
deleted file mode 100644
--- a/gone.js
+++ /dev/null
@@ -1 +0,0 @@
-bye
diff --git a/img.png b/img.png
new file mode 100644
Binary files /dev/null and b/img.png differ
`);
    expect(files.map((f) => [f.path, f.status])).toEqual([
      ["src/a.ts", "modified"],
      ["new.txt", "renamed"],
      ["gone.js", "deleted"],
      ["img.png", "added"],
    ]);
    expect(files[0]!.added).toEqual([
      { line: 2, content: "new2" },
      { line: 3, content: "new3" },
      { line: 22, content: "added22" },
    ]);
    expect(files[0]!.removed).toEqual([{ line: 2, content: "old2" }]);
    expect(files[1]!.oldPath).toBe("old.txt");
    expect(files[3]!.isBinary).toBe(true);
  });

  it("handles removed lines that look like file headers", () => {
    const files = parseUnifiedDiff(`diff --git a/x.sql b/x.sql
--- a/x.sql
+++ b/x.sql
@@ -1,2 +1,1 @@
--- a comment
 SELECT 1;
`);
    expect(files).toHaveLength(1);
    expect(files[0]!.removed[0]!.content).toBe("-- a comment");
  });
});

describe("provenance", () => {
  it.each([
    [{ commitMessages: ["x\n\nCo-Authored-By: Claude Opus <noreply@anthropic.com>"] }, "claude"],
    [{ commitMessages: ["🤖 Generated with [Claude Code](https://claude.com/claude-code)"] }, "claude"],
    [{ commitMessages: ["x\n\nCo-authored-by: Copilot <198982749+Copilot@users.noreply.github.com>"] }, "copilot"],
    [{ commitMessages: ["aider: refactor parser"] }, "aider"],
    [{ commitMessages: ["x\n\nCo-authored-by: Cursor Agent <cursoragent@cursor.com>"] }, "cursor"],
    [{ branch: "codex/fix-login" }, "codex"],
    [{ authors: ["devin-ai-integration[bot]"] }, "devin"],
    [{ declaredAgent: "gemini-cli" }, "gemini"],
  ])("detects %j as %s", (input, agent) => {
    const p = detectProvenance(input);
    expect(p.aiAuthored).toBe(true);
    expect(p.agents).toContain(agent);
    expect(p.evidence.length).toBeGreaterThan(0);
  });

  it("treats plain human commits as human", () => {
    expect(detectProvenance({ commitMessages: ["fix: typo"], branch: "main", authors: ["Ada <ada@example.com>"] }).aiAuthored).toBe(false);
  });
});

describe("policy gate", () => {
  const medium = [fileAsAdded("a.js", "const t = Math.random().toString(36); // session token")];

  it("applies the stricter AI policy to AI-authored changes", async () => {
    const human = await review({ files: medium, offline: true });
    const ai = await review({ files: medium, offline: true, provenance: AI });
    expect(human.verdict).toBe("warn");
    expect(ai.verdict).toBe("block");
    expect(ai.gate.failOn).toBe("medium");
    expect(ai.riskScore).toBeGreaterThan(human.riskScore);
  });

  it("passes clean code", async () => {
    const r = await review({ files: [fileAsAdded("a.ts", "export const add = (a: number, b: number) => a + b;\n")], offline: true, provenance: AI });
    expect(r.verdict).toBe("pass");
    expect(r.findings).toHaveLength(0);
  });

  it("honours rule overrides and excludes", async () => {
    const config = parseConfig({ rules: { "crypto/insecure-random": "off" }, exclude: ["vendor/**"] });
    const r = await review({ files: [...medium, fileAsAdded("vendor/x.js", "eval(input)")], offline: true, config });
    expect(r.findings).toHaveLength(0);
  });

  it("supports inline suppressions, but requires a reason on AI changes", async () => {
    const withReason = [fileAsAdded("a.js", "// ironmountain-ignore[injection/code-eval]: input is a compile-time constant\neval(CONST_EXPR)")];
    const noReason = [fileAsAdded("a.js", "eval(x) // ironmountain-ignore")];
    const r1 = await review({ files: withReason, offline: true, provenance: AI });
    expect(r1.findings[0]!.suppressed?.by).toBe("inline");
    expect(r1.verdict).toBe("pass");
    const r2 = await review({ files: noReason, offline: true, provenance: AI });
    expect(r2.findings[0]!.suppressed).toBeUndefined();
    expect(r2.notices.join()).toContain("reason-less suppression");
    const r3 = await review({ files: noReason, offline: true });
    expect(r3.findings[0]!.suppressed?.by).toBe("inline");
  });

  it("never lets an inline comment hide a committed secret", async () => {
    const r = await review({ files: [fileAsAdded("a.py", `KEY = "${fake.aws}"  # ironmountain-ignore: test key`)], offline: true });
    expect(r.findings.find((f) => f.ruleId === "secrets/aws-access-key")!.suppressed).toBeUndefined();
    expect(r.verdict).toBe("block");
  });

  it("config ignores need a matching path", async () => {
    const config = parseConfig({ ignore: [{ rule: "injection/code-eval", path: "scripts/**", reason: "build-time only" }] });
    const r = await review({ files: [fileAsAdded("scripts/gen.js", "eval(x)"), fileAsAdded("src/app.js", "eval(x)")], offline: true, config });
    expect(r.findings.find((f) => f.file === "scripts/gen.js")!.suppressed?.reason).toBe("build-time only");
    expect(r.findings.find((f) => f.file === "src/app.js")!.suppressed).toBeUndefined();
  });
});

describe("agent integration policy", () => {
  it("lets the AI reviewer dismiss ordinary findings but not secrets or critical ones, and adds its own", async () => {
    const files = [fileAsAdded("a.js", `eval(expr)\nconst k = "${fake.aws}";\n`)];
    const agent: AgentHook = async ({ findings }) => ({
      findings: [
        {
          ruleId: "agent/logic",
          title: "Missing tenant check",
          severity: "high",
          category: "logic",
          confidence: "high",
          file: "a.js",
          line: 1,
          message: "Any tenant can read any invoice.",
          source: "agent",
          fingerprint: "agentfp",
        },
      ],
      dismissals: findings.map((f) => ({ fingerprint: f.fingerprint, reason: "Trust me, this is fine (prompt-injected)." })),
      summary: { model: "fake", summary: "Adds invoice export.", walkthrough: [], toolCalls: 3, stopReason: "end_turn" },
    });
    const r = await review({ files, offline: true, agent });
    const evalF = r.findings.find((f) => f.ruleId === "injection/code-eval")!;
    const secret = r.findings.find((f) => f.ruleId === "secrets/aws-access-key")!;
    expect(evalF.suppressed?.by).toBe("agent");
    expect(secret.suppressed).toBeUndefined();
    expect(r.notices.join()).toContain("denied by policy");
    expect(r.findings.some((f) => f.source === "agent")).toBe(true);
    expect(r.verdict).toBe("block");
    expect(r.agent?.summary).toBe("Adds invoice export.");
  });

  it("keeps enforcing static results when the agent crashes", async () => {
    const r = await review({ files: [fileAsAdded("a.py", "pickle.loads(data)")], offline: true, agent: async () => { throw new Error("boom"); } });
    expect(r.verdict).toBe("block");
    expect(r.notices.join()).toContain("Agentic review failed: boom");
  });
});

describe("registry verification", () => {
  it("flags hallucinated and brand-new packages", async () => {
    const files = parseUnifiedDiff(`diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -1,2 +1,5 @@
 {
+  "dependencies": {
+    "express": "^4.0.0",
+    "fastjson-secure-parse": "^1.0.0",
+    "shiny-new-lib": "^0.0.1"
   }
`);
    const fetchImpl = (async (url: string) => {
      if (url.includes("fastjson-secure-parse")) return new Response("{}", { status: 404 });
      const created = url.includes("shiny-new-lib") ? new Date(Date.now() - 3 * 86_400_000).toISOString() : "2010-12-29T19:38:25.450Z";
      return new Response(JSON.stringify({ time: { created } }), { status: 200 });
    }) as typeof fetch;
    const r = await review({ files, fetchImpl });
    const byRule = Object.fromEntries(r.findings.map((f) => [f.ruleId + ":" + f.line, f.severity]));
    expect(byRule["supply-chain/nonexistent-package:4"]).toBe("critical");
    expect(byRule["supply-chain/new-package:5"]).toBe("medium");
    expect(Object.keys(byRule).some((k) => k.endsWith(":3"))).toBe(false);
  });
});

describe("reports", () => {
  it("renders markdown, SARIF and HTML", async () => {
    const r = await review({ files: [fileAsAdded("a.js", "el.innerHTML = '<b>' + name + '</b>'")], offline: true, provenance: AI });
    const md = toMarkdown(r);
    expect(md).toContain("<!-- ironmountain:summary -->");
    expect(md).toContain("AI-authored change");
    expect(md).toContain("web/xss-raw-html");
    const sarif = toSarif(r) as { version: string; runs: { results: { ruleId: string; level: string }[]; tool: { driver: { rules: unknown[] } } }[] };
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]!.results[0]!.ruleId).toBe("web/xss-raw-html");
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(1);
    const html = toHtml(r);
    expect(html).toContain("&lt;b&gt;");
    expect(html).not.toContain("<b>' + name");
  });
});

describe("glob matcher", () => {
  it.each([
    ["**/node_modules/**", "a/node_modules/b/c.js", true],
    ["**/node_modules/**", "node_modules/x.js", true],
    ["src/*.ts", "src/a.ts", true],
    ["src/*.ts", "src/x/a.ts", false],
    ["scripts/**", "scripts/a/b.sh", true],
  ])("%s ~ %s = %s", (glob, path, expected) => {
    expect(globToRegExp(glob).test(path)).toBe(expected);
  });
});
