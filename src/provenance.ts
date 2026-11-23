import type { AgentName, Provenance } from "./types.js";

interface Signal {
  agent: AgentName;
  re: RegExp;
}

// Trailers, footers and conventions that AI coding tools leave on commits/PRs.
const SIGNALS: Signal[] = [
  { agent: "claude", re: /Co-Authored-By:\s*Claude\b|Generated with \[?Claude Code|claude\.(ai|com)\/(code|claude-code)|noreply@anthropic\.com|Claude-Session:/i },
  { agent: "copilot", re: /Co-authored-by:\s*(GitHub\s*)?Copilot|copilot-swe-agent|\bCopilot Autofix\b|198982749\+Copilot@users\.noreply/i },
  { agent: "cursor", re: /Co-authored-by:\s*Cursor|cursoragent@cursor\.com|Generated (by|with) Cursor|Cursor Agent/i },
  { agent: "codex", re: /Co-authored-by:\s*(OpenAI\s*)?Codex|chatgpt-codex-connector|Generated (by|with) (OpenAI )?Codex|codex@openai\.com/i },
  { agent: "gemini", re: /Co-authored-by:\s*Gemini|gemini-code-assist|Generated (by|with) Gemini|Gemini CLI/i },
  { agent: "devin", re: /devin-ai-integration|Devin AI|devin\.ai\/sessions|Co-authored-by:\s*Devin/i },
  { agent: "aider", re: /^aider: |Co-authored-by:\s*aider|\(aider\)\s*</im },
  { agent: "windsurf", re: /Windsurf|Codeium|Cascade \(AI\)/i },
  { agent: "amazon-q", re: /Amazon Q Developer|amazon-q-developer|Co-authored-by:\s*Amazon Q/i },
  { agent: "jules", re: /google-labs-jules|Jules \(Google\)|jules\.google/i },
  { agent: "other-ai", re: /Co-authored-by:\s*[^<\n]*(\bAI\b|\bbot\b|LLM|GPT|assistant)|Generated (by|with) (an? )?(AI|LLM|ChatGPT|GPT-\d)|sweep-ai|openhands|all-hands-ai|tabnine|bolt\.new|lovable|v0\.dev|replit agent/i },
];

const BRANCH_PREFIXES: [RegExp, AgentName][] = [
  [/^claude\//i, "claude"],
  [/^copilot\//i, "copilot"],
  [/^cursor\//i, "cursor"],
  [/^codex\//i, "codex"],
  [/^devin\//i, "devin"],
  [/^(jules|google-labs-jules)\//i, "jules"],
  [/^(gemini|gemini-cli)\//i, "gemini"],
  [/^aider\//i, "aider"],
];

const BOT_AUTHORS: [RegExp, AgentName][] = [
  [/^Copilot$|copilot-swe-agent/i, "copilot"],
  [/devin-ai-integration/i, "devin"],
  [/chatgpt-codex-connector/i, "codex"],
  [/google-labs-jules/i, "jules"],
  [/claude\[bot\]|anthropic/i, "claude"],
  [/cursor/i, "cursor"],
];

export interface ProvenanceInput {
  commitMessages?: string[];
  authors?: string[];
  branch?: string;
  prBody?: string;
  prTitle?: string;
  /** Explicit declaration from a caller such as the MCP server or Claude Code hook. */
  declaredAgent?: string;
}

/** Detect whether a change was produced by an AI coding agent, and which one. */
export function detectProvenance(input: ProvenanceInput): Provenance {
  const agents = new Set<AgentName>();
  const evidence: string[] = [];

  const scan = (text: string, where: string) => {
    for (const s of SIGNALS) {
      const m = s.re.exec(text);
      if (m && !agents.has(s.agent)) {
        agents.add(s.agent);
        evidence.push(`${where}: "${m[0].trim().slice(0, 80)}"`);
      }
    }
  };

  input.commitMessages?.forEach((msg, i) => scan(msg, `commit #${i + 1}`));
  if (input.prBody) scan(input.prBody, "PR description");
  if (input.prTitle) scan(input.prTitle, "PR title");

  if (input.branch) {
    for (const [re, agent] of BRANCH_PREFIXES) {
      if (re.test(input.branch) && !agents.has(agent)) {
        agents.add(agent);
        evidence.push(`branch name "${input.branch}"`);
      }
    }
  }
  for (const author of input.authors ?? []) {
    for (const [re, agent] of BOT_AUTHORS) {
      if (re.test(author) && !agents.has(agent)) {
        agents.add(agent);
        evidence.push(`author "${author}"`);
      }
    }
  }
  if (input.declaredAgent) {
    const known: AgentName[] = ["claude", "copilot", "cursor", "codex", "gemini", "devin", "aider", "windsurf", "amazon-q", "jules"];
    const a = known.find((k) => input.declaredAgent!.toLowerCase().includes(k)) ?? "other-ai";
    if (!agents.has(a)) {
      agents.add(a);
      evidence.push(`declared by caller: ${input.declaredAgent}`);
    }
  }

  return { aiAuthored: agents.size > 0, agents: [...agents], evidence };
}

export const HUMAN_PROVENANCE: Provenance = { aiAuthored: false, agents: [], evidence: [] };
