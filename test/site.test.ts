import { describe, expect, it } from "vitest";
// @ts-expect-error - plain JS Vercel function
import { GET, POST } from "../api/scan.js";

const post = (body: unknown) =>
  POST(new Request("http://x/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body) }));

describe("playground API (/api/scan)", () => {
  it("scans a snippet and applies the AI policy when asked", async () => {
    const res = await post({ filename: "a.py", content: "import pickle\npickle.loads(data)\n", aiAuthored: true });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.verdict).toBe("block");
    expect(data.aiAuthored).toBe(true);
    expect(data.findings[0].ruleId).toBe("injection/unsafe-deserialization");
  });

  it("passes clean code", async () => {
    const data = await (await post({ filename: "a.ts", content: "export const x = 1;\n" })).json();
    expect(data.verdict).toBe("pass");
  });

  it("rejects bad input", async () => {
    expect((await post("not json")).status).toBe(400);
    expect((await post({ content: "" })).status).toBe(400);
    expect((await post({ content: "x".repeat(250_000) })).status).toBe(413);
    expect((await GET()).status).toBe(405);
  });

  it("sanitizes the filename", async () => {
    const data = await (await post({ filename: "../../<script>.js", content: "eval(x)" })).json();
    expect(data.findings[0].ruleId).toBe("injection/code-eval");
  });
});
