import { isCode, isCommentLine, lineRule, type Rule, type RuleHit } from "./types.js";

const isTestPath = (p: string) => /(^|\/)(__tests__|tests?|spec|e2e)(\/|$)|[._-](test|spec)\.[a-z]+$|_test\.go$|^test_[^/]*\.py$|\/test_[^/]*\.py$/i.test(p);

/**
 * Files that steer AI coding agents. Changes here can silently widen an
 * agent's permissions or plant instructions for future sessions.
 */
const AGENT_CONFIG =
  /(^|\/)(CLAUDE\.md|CLAUDE\.local\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|\.roorules|\.goosehints|\.aider\.conf\.yml|copilot-instructions\.md|\.mcp\.json|mcp\.json|\.claude\/settings(\.local)?\.json|\.claude\/(commands|agents|skills|hooks)\/.+|\.cursor\/rules\/.+|\.cursor\/mcp\.json|\.vscode\/mcp\.json|\.gemini\/settings\.json|\.codex\/.+|\.github\/instructions\/.+\.md|\.github\/prompts\/.+)$/i;

const SECURITY_IDENT =
  /\b(authenticate|authenticated|isAuthenticated|is_authenticated|requireAuth|require_auth|ensureAuth|login_required|@login_required|permission_required|@permission_required|PreAuthorize|@Secured|RolesAllowed|authorize|authorization|isAuthorized|is_authorized|checkPermission|check_permission|has_permission|hasRole|verify(Token|Signature|Jwt|JWT|Webhook|Hmac|Csrf)?|verify_(token|signature|jwt|webhook|hmac|csrf)|validate(Token|Input|Request|Signature|Origin)?|sanitize\w*|escape(Html|HTML|Sql)?|csrf\w*|CSRF\w*|rateLimit\w*|rate_limit\w*|limiter|helmet|timingSafeEqual|compare_digest|ConstantTimeCompare|bcrypt\.compare|checkpw|hmac\.\w+|allowlist|whitelist|denylist|blacklist)\b/;

export const aiIntegrityRules: Rule[] = [
  lineRule({
    id: "ai/trojan-source",
    scansDocs: true,
    title: "Hidden Unicode control characters (Trojan Source)",
    severity: "critical",
    category: "ai-integrity",
    confidence: "high",
    cwe: ["CWE-1007", "CWE-451"],
    description:
      "Bidirectional overrides and zero-width characters make code render differently from how it compiles. They hide backdoors from human reviewers and smuggle instructions to AI agents.",
    remediation: "Remove the invisible characters. If they are genuinely required in a string literal, use explicit escape sequences.",
    patterns: [/[\u202A-\u202E\u2066-\u2069\u200B-\u200F\u2060-\u2064\uFEFF\u00AD]|[\u{E0000}-\u{E007F}]/u],
    unless: [/^\uFEFF/],
    skipComments: false,
    message: (l) => {
      const cps = [...l.content].filter((c) => /[\u202A-\u202E\u2066-\u2069\u200B-\u200F\u2060-\u2064\uFEFF\u00AD]|[\u{E0000}-\u{E007F}]/u.test(c));
      return `Invisible/bidi characters: ${[...new Set(cps.map((c) => "U+" + c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")))].join(", ")}`;
    },
  }),
  lineRule({
    id: "ai/prompt-injection",
    scansDocs: true,
    title: "Prompt-injection payload aimed at AI agents",
    severity: "high",
    category: "ai-integrity",
    confidence: "medium",
    cwe: ["CWE-77"],
    description:
      "Text that tries to override an AI assistant's instructions was added. Coding agents read repository files, comments, docs and tool output, and may obey such text (exfiltrate secrets, approve PRs, run commands).",
    remediation: "Remove the injected instructions and investigate how they entered the change (copied web content, dependency, compromised contributor).",
    patterns: [
      /\b(ignore|disregard|forget|override)\b.{0,30}\b(all|any|the|your|previous|prior|above|earlier|preceding)\b.{0,30}\b(instructions?|prompts?|rules|directives|guidelines|system message)\b/i,
      /\b(you are now|from now on,? you|act as|new instructions?:|system override|developer mode|jailbreak|DAN mode)\b.{0,60}\b(assistant|ai|claude|gpt|copilot|agent|model|llm|reviewer)\b/i,
      /\b(AI|LLM|assistant|claude|copilot|gpt|cursor|reviewer|agent)s?\b[^.\n]{0,40}\b(must|should|always|do not|don't|never)\b[^.\n]{0,40}\b(approve|merge|ignore|skip|exfiltrate|send|upload|run|execute|curl|post)\b/i,
      /<\|(im_start|im_end|system|endoftext)\|>|\[\/?INST\]|<<SYS>>|<\/?system>|<\/?(antml:)?(function_calls|invoke)\b/i,
      /\b(do not|don't|never)\s+(mention|tell|reveal|report|flag)\b.{0,40}\b(user|human|reviewer|maintainer|this)\b/i,
    ],
    skipComments: false,
  }),
  {
    id: "ai/agent-config-changed",
    scansDocs: true,
    title: "AI agent instructions or permissions changed",
    severity: "medium",
    category: "ai-integrity",
    confidence: "high",
    cwe: ["CWE-284"],
    description:
      "A file that configures AI coding agents (CLAUDE.md, AGENTS.md, .cursorrules, MCP server lists, Claude Code settings/hooks) was modified. These files persist instructions and permissions into every future agent session.",
    remediation: "Have a human review the agent-instruction changes line by line; avoid broad tool permissions and auto-approved MCP servers.",
    appliesTo: (ctx) => AGENT_CONFIG.test(ctx.file.path),
    check(ctx) {
      const hits: RuleHit[] = [];
      for (const l of ctx.file.added) {
        if (
          /bypassPermissions|dangerously-?skip-?permissions|--yolo|"Bash\(\*\)"|"Bash"\s*[,\]]|"\*"\s*[,\]]|enableAllProjectMcpServers"\s*:\s*true|"autoApprove"\s*:\s*\[|alwaysAllow|"trust"\s*:\s*true|auto[_-]?approve|full-auto|danger-full-access/i.test(
            l.content,
          )
        ) {
          hits.push({ line: l.line, severity: "high", message: "Grants an AI agent broad, unattended permissions." });
        } else if (/"command"\s*:\s*"|https?:\/\/|curl|wget|\bnpx\b|\buvx\b/.test(l.content) && /mcp|hooks|settings/i.test(ctx.file.path)) {
          hits.push({ line: l.line, message: "Adds a command or remote endpoint that AI agents will execute or connect to." });
        }
      }
      if (hits.length === 0 && (ctx.file.added.length > 0 || ctx.file.status === "deleted")) {
        const first = ctx.file.added[0]?.line ?? 1;
        hits.push({ line: first, severity: "low", message: `Agent configuration \`${ctx.file.path}\` changed; review for persisted instructions.` });
      }
      return hits;
    },
  },
  {
    id: "ai/security-control-removed",
    title: "Security control removed",
    severity: "high",
    category: "ai-integrity",
    confidence: "medium",
    cwe: ["CWE-693"],
    description:
      "A line containing an authentication, authorization, validation or rate-limiting control was deleted and not re-added elsewhere in the file. Coding agents frequently remove checks to make a failing test or request pass.",
    remediation: "Confirm the control was intentionally moved or replaced; restore it otherwise.",
    appliesTo: isCode,
    check(ctx) {
      const addedText = ctx.file.added.map((l) => l.content).join("\n");
      const hits: RuleHit[] = [];
      const seen = new Set<string>();
      for (const r of ctx.file.removed) {
        if (isCommentLine(r.content)) continue;
        const m = SECURITY_IDENT.exec(r.content);
        if (!m) continue;
        const ident = m[0];
        if (seen.has(ident) || addedText.includes(ident)) continue;
        seen.add(ident);
        // Report against the nearest new-file line so it can be anchored in a PR review.
        const anchor = ctx.file.hunks.find((h) => r.line >= h.oldStart && r.line <= h.oldStart + h.oldLines);
        hits.push({
          line: anchor ? Math.max(1, anchor.newStart + (r.line - anchor.oldStart)) : r.line,
          snippet: "- " + r.content.trim(),
          message: `Removed security control \`${ident}\` with no replacement in this file.`,
        });
      }
      return hits;
    },
  },
  lineRule({
    id: "ai/auth-bypass-flag",
    title: "Authentication / verification bypass switch",
    severity: "high",
    category: "ai-integrity",
    confidence: "medium",
    cwe: ["CWE-288", "CWE-1188"],
    description: "A flag or condition that skips authentication, verification or security checks was introduced. Such shortcuts often ship to production by accident.",
    remediation: "Remove the bypass; use proper test fixtures or mocks instead of production code paths.",
    patterns: [
      /\b(SKIP|BYPASS|DISABLE|NO|IGNORE)_?(AUTH|AUTHN|AUTHZ|AUTHENTICATION|AUTHORIZATION|LOGIN|VERIFICATION|VERIFY|SIGNATURE|SECURITY|SSL|TLS|CSRF|2FA|MFA|OTP|CAPTCHA|RATE_?LIMIT)\b/i,
      /\b(skip|bypass|disable)(Auth|Authentication|Authorization|Verification|SignatureCheck|Security|Csrf|Mfa|RateLimit)\s*[:=]\s*(true|True|1)/,
      /if\s*\(?\s*(process\.env\.NODE_ENV|os\.environ(\.get)?\(?\[?["']ENV|ENV\[)[^)]*(dev|development|test|local)[^)]*\)?\s*[:{]?\s*(return\s+(next\(\)|true|True)|next\(\))/i,
    ],
    skipComments: true,
  }),
  {
    id: "ai/auth-stub",
    title: "Security check stubbed to always succeed",
    severity: "critical",
    category: "ai-integrity",
    confidence: "medium",
    cwe: ["CWE-287", "CWE-862"],
    description: "An authentication/authorization/verification function returns a constant success value. This is a classic AI placeholder that grants everyone access.",
    remediation: "Implement the real check, or fail closed (return false / raise) until it exists.",
    appliesTo: isCode,
    check(ctx) {
      const hits: RuleHit[] = [];
      const lines = ctx.file.added;
      for (let i = 0; i < lines.length; i++) {
        const l = lines[i]!;
        if (!/\b(def|function|func|fn|async|public|private|protected|static|bool|boolean)\b[^\n]*\b(is_?auth\w*|is_?admin|is_?authori[sz]ed|has_?permission|has_?role|can_?access|check_?(auth|permission|access|role)\w*|verify\w*|validate_?(token|signature|session|user|password)\w*|authenticate\w*|authori[sz]e\w*)\s*[(=:]/i.test(l.content) &&
            !/\b(const|let|var)\s+(is_?auth\w*|is_?admin|has_?permission|can_?access|verify\w*|authori[sz]e\w*)\s*=\s*(async\s*)?\(/i.test(l.content)) continue;
        const body = lines.slice(i, i + 4).filter((x) => x.line <= l.line + 3);
        const ret = body.find((x, j) => (j > 0 || /=>|\{\s*return|:\s*return/.test(x.content)) && /\breturn\s+(true|True|1|nil|None)\b\s*;?\s*(\}|$|#|\/\/)|=>\s*(true|\{\s*return\s+true)|\bOk\(\(\)\)\s*$|^\s*pass\s*$/.test(x.content));
        if (ret) hits.push({ line: ret.line, snippet: l.content.trim() + " … " + ret.content.trim() });
      }
      return hits;
    },
  },
  lineRule({
    id: "ai/hardcoded-credential-check",
    title: "Hardcoded credential comparison (backdoor)",
    severity: "critical",
    category: "ai-integrity",
    confidence: "medium",
    cwe: ["CWE-798", "CWE-912"],
    description: "Login logic compares a username/password/token to a literal, creating a backdoor account.",
    remediation: "Authenticate against the user store with a password hash; remove literal credentials.",
    appliesTo: isCode,
    patterns: [/\b(password|passwd|pwd|token|api_?key|secret)\w*\s*(===?|eq|\.equals\()\s*["'][^"']{3,}["']/i, /["'][^"']{3,}["']\s*===?\s*\w*(password|passwd|token|secret)\b/i],
    unless: [/(===?|!==?)\s*["'](undefined|null|string|object|true|false|password|text|hidden|bearer)["']/i],
  }),
  lineRule({
    id: "ai/security-todo",
    title: "Unfinished security work left in code",
    severity: "medium",
    category: "ai-integrity",
    confidence: "medium",
    cwe: ["CWE-1188"],
    description: "A TODO/FIXME/placeholder says authentication, validation, sanitization or encryption is not implemented yet. Generated code often ships with these stubs.",
    remediation: "Implement the control before merging, or gate the feature off.",
    patterns: [/(\/\/|#|\/\*|^\s*\*|--|<!--|""")\s*(TODO|FIXME|XXX|HACK)\b[^\n]*\b(auth\w*|security|secur\w*|validat\w*|saniti[sz]\w*|escap\w*|permission\w*|encrypt\w*|csrf|rate.?limit|verify|verification|access control|injection)\b/i, /\bin (a )?real (app|application|implementation|world)\b[^\n]*\b(should|would|must)\b/i, /\bfor (demo|simplicity|now)\b[^\n]*\b(skip|disable|hardcod|bypass|trust|without)\w*/i],
    skipComments: false,
  }),
  lineRule({
    id: "ai/test-disabled",
    title: "Test disabled or focused",
    severity: "medium",
    category: "ai-integrity",
    confidence: "high",
    cwe: ["CWE-1164"],
    description: "Skipping tests (or focusing a single one, which silently skips the rest) is a common way agents make a red build green without fixing the problem.",
    remediation: "Fix the underlying failure instead of disabling the test; if a skip is necessary, link an issue.",
    patterns: [
      /\b(it|test|describe|context|suite)\.(skip|only|todo)\s*\(/,
      /\b(xit|xdescribe|xtest|fit|fdescribe)\s*\(/,
      /@pytest\.mark\.(skip|xfail)\b|@unittest\.skip|pytest\.skip\(/,
      /\bt\.Skip(f|Now)?\(/,
      /@Disabled\b|@Ignore\b|\[Ignore\]|\[Fact\(Skip\s*=/,
      /#\[ignore\]/,
      /--passWithNoTests|\|\|\s*true\s*$|continue-on-error\s*:\s*true/,
    ],
    skipComments: true,
  }),
  {
    id: "ai/test-weakened",
    title: "Tests deleted or assertions removed",
    severity: "medium",
    category: "ai-integrity",
    confidence: "medium",
    cwe: ["CWE-1164"],
    description: "Test files were deleted or assertions removed on net. Agents under pressure to pass CI frequently weaken the tests instead of fixing code.",
    remediation: "Verify the removed coverage is truly obsolete; restore assertions otherwise.",
    appliesTo: (ctx) => isTestPath(ctx.file.path),
    check(ctx) {
      if (ctx.file.status === "deleted") return [{ line: 1, message: `Test file \`${ctx.file.path}\` was deleted.` }];
      const ASSERT = /\b(assert\w*|expect\s*\(|should\.|\.to(Be|Equal|Throw|Match|Have)\w*|require\.\w+\(|t\.(Error|Fatal|Fail)\w*\()/;
      const removed = ctx.file.removed.filter((l) => ASSERT.test(l.content)).length;
      const added = ctx.file.added.filter((l) => ASSERT.test(l.content)).length;
      if (removed - added >= 2) {
        const line = ctx.file.hunks[0]?.newStart ?? 1;
        return [{ line, message: `${removed - added} net assertion(s) removed from \`${ctx.file.path}\`.` }];
      }
      return [];
    },
  },
  lineRule({
    id: "ai/suppression-added",
    title: "Security linter or type check suppressed",
    severity: "low",
    category: "ai-integrity",
    confidence: "high",
    cwe: ["CWE-1164"],
    description: "Inline suppressions hide real problems from scanners; when added by an agent they often silence exactly the warning that mattered.",
    remediation: "Fix the flagged code or document why the suppression is safe.",
    patterns: [
      /eslint-disable[^\n]*(security|no-eval|no-implied-eval|no-new-func|detect-|xss|no-unsanitized)/,
      /#\s*nosec\b|#\s*noqa:\s*S\d+|\/\/\s*nolint:\s*gosec|NOSONAR|nosemgrep|@SuppressWarnings\(\s*"(security|all)/i,
      /#\s*type:\s*ignore\b|@ts-ignore\b|@ts-nocheck\b|eslint-disable(?!-next-line\s+\S)\s*(\*\/)?\s*$/,
    ],
    skipComments: false,
  }),
  lineRule({
    id: "ai/obfuscated-code",
    title: "Obfuscated or encoded executable payload",
    severity: "high",
    category: "ai-integrity",
    confidence: "medium",
    cwe: ["CWE-506"],
    description: "Long encoded blobs that are decoded and executed are the hallmark of malicious code smuggled into a change.",
    remediation: "Replace with readable source; never execute decoded data.",
    patterns: [
      /\b(eval|exec|Function|execSync|system)\s*\(\s*(atob|Buffer\.from|base64\.b64decode|b64decode|base64_decode|codecs\.decode|bytes\.fromhex|unescape|decodeURIComponent|zlib\.decompress|String\.fromCharCode)\s*\(/,
      /String\.fromCharCode\(\s*(\d+\s*,\s*){15,}/,
      /(\\x[0-9a-fA-F]{2}){25,}/,
      /["'][A-Za-z0-9+/]{300,}={0,2}["']/,
      /\bpowershell(\.exe)?\b[^\n]*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i,
    ],
    skipComments: false,
  }),
  lineRule({
    id: "ai/exfiltration-endpoint",
    scansDocs: true,
    title: "Data sent to a paste / webhook / tunneling service",
    severity: "high",
    category: "data-exposure",
    confidence: "medium",
    cwe: ["CWE-200"],
    description: "Requests to request-bin, paste, tunneling or anonymous webhook services are commonly used to exfiltrate secrets from developer machines and CI.",
    remediation: "Remove the endpoint unless there is a documented business need.",
    patterns: [/\b(webhook\.site|requestbin|pipedream\.net|ngrok\.(io|app)|ngrok-free\.app|trycloudflare\.com|interact\.sh|oast\.(fun|me|pro|site|live|online)|burpcollaborator\.net|pastebin\.com\/raw|transfer\.sh|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot)/i],
    skipComments: false,
  }),
];
