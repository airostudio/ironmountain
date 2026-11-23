# 🏔️ Iron Mountain

**An agentic change-safety gate for code written by AI.**

Iron Mountain reviews every change before it ships, whether Claude Code, Copilot, Cursor, Codex, Gemini, Devin, Aider or a person wrote it, and blocks the ones that aren't safe. The workflow is modelled on CodeRabbit (a PR summary, a walkthrough, inline comments, a required check), but the focus is narrower: **security, and the specific ways AI coding agents break it.**

```
 BLOCK  risk 100/100 · 12 finding(s) · 2 files · 181 ms
 AI-authored change (claude); stricter policy applied.

 CRITICAL  Dependency does not exist on the registry   package.json:5
           `react-super-auth-helper-xyz` is not published on npm. AI assistants hallucinate
           package names, and attackers register them ("slopsquatting").
 CRITICAL  Security check stubbed to always succeed    src/app.js:13
 HIGH      Security control removed                    src/app.js:3   - app.get("/admin", requireAuth, …)
 HIGH      SQL query built from string interpolation   src/app.js:8
 …
```

## Why

AI agents write code fast and with confidence, and they fail in recognisable ways that a normal linter doesn't look for:

| Failure mode | What Iron Mountain does |
|---|---|
| Removes `requireAuth` / CSRF / rate limiting to make a request or test pass | Diff-aware `ai/security-control-removed` checks deleted lines for security controls that weren't re-added |
| Stubs checks: `isAdmin() { return true }` | `ai/auth-stub` (critical) |
| Invents packages that don't exist, so attackers register them | Live npm/PyPI lookup flags **nonexistent** and **brand-new** packages, plus typosquats and known-malicious names |
| Leaves example credentials, `verify=False`, `DEBUG=True`, `TODO: add auth` in the code | Secrets, TLS, config and `ai/security-todo` rules |
| Skips or deletes tests to get CI green | `ai/test-disabled`, `ai/test-weakened` |
| Gets prompt-injected by repo content, or plants instructions for the next agent | `ai/prompt-injection`, `ai/trojan-source` (invisible bidi/zero-width chars), `ai/agent-config-changed` (CLAUDE.md, `.cursorrules`, MCP configs, `bypassPermissions`) |
| Writes GitHub Actions that are open to script injection or "pwn requests" | `ci/*` rules |

Changes that can be traced to an AI agent (commit trailers such as `Co-Authored-By: Claude`, agent branch names such as `claude/…` or `codex/…`, bot authors, or a caller that says so) automatically get a **stricter gate**: by default they block at `medium` instead of `high`.

## How it works

```
             ┌────────────── sources ──────────────┐
 git diff ───┤ CLI · pre-commit · Claude Code hook │
 PR diff  ───┤ GitHub Action · GitHub App webhook  │──► parse diff ──► provenance (which AI?)
 MCP call ───┤ Cursor/Windsurf/Codex/Gemini/…      │                      │
             └─────────────────────────────────────┘                      ▼
                     ┌──────────────────────────────────────────────────────────┐
                     │ 1. Static engine: 75 rules, diff-aware, ~100 ms           │
                     │ 2. Supply chain: npm / PyPI registry verification         │
                     │ 3. Agentic reviewer (Claude): reads the repo with tools,  │
                     │    triages static findings, hunts logic/authz flaws       │
                     │ 4. Policy gate: suppressions, AI-strict thresholds        │
                     └──────────────────────────────────────────────────────────┘
                                          │
       terminal · Markdown PR comment · inline review · check run · SARIF · HTML · JSON
```

**The agentic reviewer** runs a Claude tool-use loop (`claude-opus-5-5`, adaptive thinking, effort `high`) with read-only tools: `read_file`, `search_code`, `list_directory`, `get_file_diff`. It reports through `report_finding`, `triage_static_finding` and `submit_review`, and writes the PR summary and per-file walkthrough. It runs whenever Anthropic credentials are available (`ANTHROPIC_API_KEY`, or a profile from `ant auth login`); without them the static engine still enforces the gate. Requests opt in to server-side refusal fallbacks (`fallbacks: "default"`), so a safety-classifier decline on security content is retried on a fallback model rather than failing the review.

### Safety design: the reviewer can't be talked out of a block

Code under review is untrusted, and so is an LLM that reads it. The design accounts for both:

- The diff and every tool result are fenced as `<untrusted_change>`, and the system prompt tells the model never to follow instructions found there and to report any it sees.
- The agent can only **add** findings or **dismiss** findings. It cannot dismiss anything `critical` or anything in the `secrets`, `ai-integrity` or `supply-chain` categories (configurable). Each attempt is denied and logged.
- Agent tools are read-only and confined to the repository. Paths are canonicalised (`..`, absolute paths and symlinks that escape the repo are refused) and `.git/` is off-limits.
- If the agent crashes, refuses or runs out of budget, static results are still enforced.
- In GitHub App mode, policy is read from the **base** branch, so a PR can't loosen its own gate.
- Inline suppressions (`ironmountain-ignore[rule]: reason`) need a written reason on AI-authored changes, and can never hide a committed secret.
- Webhooks are verified with HMAC-SHA256 using a constant-time comparison. Re-review commands (`/ironmountain review`) are only accepted from repository collaborators.

## Quick start

> The npm package isn't published yet. Until it is, build from source. Before you publish, reserve the `ironmountain` name on npm, so nobody can squat it in the meantime.

```bash
git clone https://github.com/airostudio/ironmountain && cd ironmountain
```

```bash
npm ci && npm run build && npm link
```

Then, inside any repository:

```bash
ironmountain review                      # uncommitted + untracked changes
```

```bash
ironmountain review --base origin/main   # everything on this branch
```

```bash
ironmountain scan src/                   # audit whole files, not just a diff
```

```bash
ironmountain init --claude --git-hooks --github-action
```

`init` writes `.ironmountain.yml`, the Claude Code hooks, `.mcp.json`, git `pre-commit`/`pre-push` hooks and a workflow. Hooks always call the CLI you installed, never `npx --yes`, so a squatted package name can't run inside your hooks.

Exit codes: `0` pass/warn · `1` blocked · `2` error.

## Use it from every AI coding tool

### Claude Code: real-time feedback loop

`ironmountain init --claude` adds two hooks to `.claude/settings.json`:

- **PostToolUse** (`Write|Edit|MultiEdit`) scans exactly the lines Claude just wrote. On a finding it exits `2`, which sends the issue back to Claude so it fixes it straight away.
- **Stop** reviews the whole working tree when Claude says it's finished, and sends it back to work if the change would be blocked. It respects `stop_hook_active`, so it can't loop forever.

### Any MCP client (Claude Desktop, Cursor, Windsurf, VS Code, Codex CLI, Gemini CLI, …)

`ironmountain mcp` is a stdio MCP server with four tools:

| Tool | Use |
|---|---|
| `review_changes` | Review the workspace's git changes (`base`, `staged`, optional `deep` agentic review) |
| `review_diff` | Review a unified diff |
| `scan_code` | Scan a snippet or file before or after writing it |
| `list_rules` | Browse rules and remediation guidance |

Each tool takes an optional `agent` name (`"cursor"`, `"codex"`, …), which applies the AI policy. Example configurations, using the path printed by `which ironmountain`:

```jsonc
// Claude Desktop (claude_desktop_config.json), Cursor (.cursor/mcp.json), Windsurf, Gemini CLI (.gemini/settings.json)
{ "mcpServers": { "ironmountain": { "command": "ironmountain", "args": ["mcp"] } } }
```

```jsonc
// VS Code (.vscode/mcp.json)
{ "servers": { "ironmountain": { "type": "stdio", "command": "ironmountain", "args": ["mcp"] } } }
```

```toml
# Codex CLI (~/.codex/config.toml)
[mcp_servers.ironmountain]
command = "ironmountain"
args = ["mcp"]
```

Claude Code: `claude mcp add ironmountain -- ironmountain mcp`

Add a line like this to your agent instructions (CLAUDE.md, AGENTS.md, `.cursorrules`): *"Before reporting a task as done, call `review_changes` and fix every finding at or above the gate."*

### Git hooks (any editor, any agent)

```bash
ironmountain init --git-hooks   # pre-commit: staged changes · pre-push: branch vs upstream
```

## GitHub

### GitHub Action

```yaml
# .github/workflows/ironmountain.yml
on: { pull_request: { types: [opened, synchronize, reopened, ready_for_review] } }
permissions: { contents: read, pull-requests: write, checks: write, security-events: write }
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: airostudio/ironmountain@<commit-sha>   # pin to a SHA
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}   # optional; enables the agentic reviewer
          # fail-on: high
          # agent: auto | true | false
```

On each PR this posts a sticky summary comment (verdict, risk score, AI provenance, walkthrough, findings), an inline review on the changed lines (`REQUEST_CHANGES` when blocked), and an **Iron Mountain** check run you can make a required status check. It also uploads SARIF to code scanning and writes a job summary. Outputs: `verdict`, `risk-score`, `ai-authored`.

### GitHub App (hosted bot)

```bash
docker build -t ironmountain .
```

```bash
docker run -p 3000:3000 -e GITHUB_WEBHOOK_SECRET=… -e GITHUB_APP_ID=… -e GITHUB_APP_PRIVATE_KEY_PATH=/key.pem -v $PWD/key.pem:/key.pem:ro -e ANTHROPIC_API_KEY=… ironmountain
```

Point the App's webhook at `POST /webhook`, subscribe to *Pull request* and *Issue comment* events, and grant Pull requests (write), Checks (write) and Contents (read). `GET /` shows a dashboard of recent reviews, and `GET /healthz` is the health check. Comment `/ironmountain review` on a PR to re-run. For one repository you can use `GITHUB_TOKEN` instead of App credentials.

To review a PR from your terminal: `GITHUB_TOKEN=… ironmountain pr owner/repo#123 [--post]`.

## Configuration

`.ironmountain.yml` (full annotated default via `ironmountain init`):

```yaml
failOn: high            # block at/above this severity
warnOn: medium
ai:                     # stricter gate for AI-authored changes
  failOn: medium
  warnOn: low
  requireSuppressionReason: true
exclude: ["**/node_modules/**", "**/dist/**", "**/vendor/**"]
rules:
  web/plain-http: off
  crypto/weak-hash: low
  injection/sql-string-building: { paths: ["src/**"] }
ignore:                 # accepted risks: each one needs a reason
  - rule: injection/code-eval
    path: "scripts/**"
    reason: build-time only, inputs are constant
supplyChain:
  verifyRegistry: true  # npm / PyPI existence + age check
  newPackageDays: 30
agent:
  enabled: true
  model: claude-opus-5-5
  effort: high          # low | medium | high | xhigh | max
  maxToolCalls: 40
  nonDismissible: [secrets, ai-integrity, supply-chain]
  instructions: |
    Our handlers must call requireTenant() before touching the database.
```

Inline suppression: put this on the flagged line or the line above it:

```js
eval(BUILD_EXPR); // ironmountain-ignore[injection/code-eval]: compile-time constant from build.json
```

## Rules

Covers JS/TS, Python, Go, Java/Kotlin, Ruby, PHP, C#, Rust, shell, Dockerfile, Kubernetes/Compose YAML, Terraform, GitHub Actions and package manifests. Regenerate this table with `npm run docs:rules`.

| Rule | Default severity | Detects | CWE |
|---|---|---|---|
| `secrets/aws-access-key` | critical | AWS access key ID |CWE-798|
| `secrets/aws-secret-key` | critical | AWS secret access key |CWE-798|
| `secrets/github-token` | critical | GitHub token |CWE-798|
| `secrets/anthropic-key` | critical | Anthropic API key |CWE-798|
| `secrets/openai-key` | critical | OpenAI API key |CWE-798|
| `secrets/google-api-key` | high | Google API key |CWE-798|
| `secrets/slack-token` | critical | Slack token |CWE-798|
| `secrets/slack-webhook` | high | Slack webhook URL |CWE-798|
| `secrets/stripe-key` | critical | Stripe live secret key |CWE-798|
| `secrets/twilio-key` | high | Twilio API key |CWE-798|
| `secrets/sendgrid-key` | critical | SendGrid API key |CWE-798|
| `secrets/npm-token` | critical | npm access token |CWE-798|
| `secrets/pypi-token` | critical | PyPI upload token |CWE-798|
| `secrets/huggingface-token` | high | Hugging Face token |CWE-798|
| `secrets/private-key` | critical | Private key |CWE-798|
| `secrets/connection-string` | high | Credentials embedded in connection string |CWE-798|
| `secrets/jwt-literal` | medium | Hardcoded JSON Web Token |CWE-798|
| `secrets/hardcoded-credential` | high | Hardcoded password or API secret |CWE-798, CWE-259|
| `injection/sql-string-building` | high | SQL query built from string interpolation |CWE-89|
| `injection/command-injection` | high | Shell command built from dynamic input |CWE-78|
| `injection/code-eval` | high | Dynamic code evaluation |CWE-94, CWE-95|
| `injection/python-exec` | high | Python exec/compile on dynamic input |CWE-94|
| `injection/unsafe-deserialization` | high | Unsafe deserialization |CWE-502|
| `injection/path-traversal` | high | File path built from request input |CWE-22|
| `injection/ssrf` | high | Server-side request to user-controlled URL |CWE-918|
| `injection/open-redirect` | medium | Open redirect |CWE-601|
| `injection/nosql-operator` | medium | NoSQL query built directly from request body |CWE-943|
| `injection/xxe` | high | XML parser with external entities enabled |CWE-611|
| `injection/template-injection` | high | Server-side template rendered from dynamic string |CWE-1336|
| `injection/regex-from-input` | low | Regular expression built from request input |CWE-1333|
| `crypto/weak-hash` | medium | Weak hash algorithm (MD5/SHA-1) |CWE-327, CWE-328|
| `crypto/password-plain-hash` | high | Password hashed with a fast hash |CWE-916|
| `crypto/insecure-random` | medium | Non-cryptographic RNG used for security value |CWE-338|
| `crypto/broken-cipher` | high | Broken cipher or mode (DES, RC4, ECB, no-IV) |CWE-327|
| `crypto/jwt-unverified` | critical | JWT signature verification disabled |CWE-347|
| `crypto/static-iv-or-salt` | medium | Hardcoded IV, nonce, or salt |CWE-329, CWE-760|
| `crypto/timing-unsafe-compare` | low | Secret compared with a non-constant-time equality |CWE-208|
| `web/xss-raw-html` | high | Raw HTML injection sink |CWE-79|
| `web/cors-wildcard` | medium | Overly permissive CORS policy |CWE-942|
| `web/csrf-disabled` | high | CSRF protection disabled |CWE-352|
| `web/insecure-cookie` | medium | Session cookie without Secure/HttpOnly |CWE-614, CWE-1004|
| `web/tls-verification-disabled` | high | TLS certificate verification disabled |CWE-295|
| `web/plain-http` | low | Credentials or API traffic over plain HTTP |CWE-319|
| `config/debug-enabled` | medium | Debug mode enabled |CWE-489, CWE-215|
| `config/world-writable` | medium | World-writable file permissions |CWE-732|
| `data/sensitive-logging` | medium | Sensitive value written to logs |CWE-532|
| `web/mass-assignment` | medium | Request body assigned directly to model |CWE-915|
| `ci/script-injection` | high | GitHub Actions script injection |CWE-78, CWE-94|
| `ci/pull-request-target-checkout` | critical | pull_request_target workflow checks out untrusted PR code |CWE-829|
| `ci/excessive-permissions` | medium | Workflow requests write-all permissions |CWE-250|
| `ci/unpinned-action` | medium | Third-party action pinned to a mutable ref |CWE-829|
| `ci/secret-exposure` | high | Secret printed or exported in CI |CWE-532|
| `infra/curl-pipe-shell` | high | Remote script piped directly into a shell |CWE-494|
| `infra/docker-root-or-latest` | low | Container runs as root or uses a floating base image |CWE-250|
| `infra/docker-secret-in-image` | high | Secret baked into container image |CWE-538|
| `infra/k8s-privileged` | high | Privileged or host-level container settings |CWE-250|
| `infra/public-exposure` | high | Cloud resource exposed to the internet |CWE-284|
| `infra/iam-wildcard` | high | IAM policy grants wildcard actions |CWE-269|
| `supply-chain/suspicious-dependency` | high | Suspicious new dependency |CWE-829, CWE-1357|
| `supply-chain/install-script` | medium | Package lifecycle install script added |CWE-829|
| `supply-chain/dependency-confusion` | high | Extra package index or trusted host configured |CWE-427|
| `supply-chain/lockfile-integrity` | high | Lockfile resolves to a non-registry or insecure URL |CWE-494|
| `ai/trojan-source` | critical | Hidden Unicode control characters (Trojan Source) |CWE-1007, CWE-451|
| `ai/prompt-injection` | high | Prompt-injection payload aimed at AI agents |CWE-77|
| `ai/agent-config-changed` | medium | AI agent instructions or permissions changed |CWE-284|
| `ai/security-control-removed` | high | Security control removed |CWE-693|
| `ai/auth-bypass-flag` | high | Authentication / verification bypass switch |CWE-288, CWE-1188|
| `ai/auth-stub` | critical | Security check stubbed to always succeed |CWE-287, CWE-862|
| `ai/hardcoded-credential-check` | critical | Hardcoded credential comparison (backdoor) |CWE-798, CWE-912|
| `ai/security-todo` | medium | Unfinished security work left in code |CWE-1188|
| `ai/test-disabled` | medium | Test disabled or focused |CWE-1164|
| `ai/test-weakened` | medium | Tests deleted or assertions removed |CWE-1164|
| `ai/suppression-added` | low | Security linter or type check suppressed |CWE-1164|
| `ai/obfuscated-code` | high | Obfuscated or encoded executable payload |CWE-506|
| `ai/exfiltration-endpoint` | high | Data sent to a paste / webhook / tunneling service |CWE-200|

Agent findings show up as `agent/<category>` with a 🤖 marker.

## Library API

```ts
import { reviewLocal, reviewDiffText, scanSnippet, review, parseUnifiedDiff, createAgentReviewer } from "ironmountain";

const report = await reviewLocal({ cwd: ".", base: "origin/main" });
if (report.verdict === "block") process.exit(1);
```

## Development

```bash
npm ci
```

```bash
npm test            # 160+ tests: rules (positive and negative), engine, policy, agent harness, GitHub, hooks, CLI
```

```bash
npm run typecheck
```

```bash
npm run selfcheck   # Iron Mountain scans its own source
```

## Limitations

- The static rules are pattern-based and diff-scoped. They're fast and explainable, but they don't do data-flow analysis. The agentic reviewer covers cross-file reasoning, and it's worth pairing Iron Mountain with a full SAST tool (CodeQL, Semgrep) on the default branch.
- Registry verification sends the names of newly added packages to registry.npmjs.org and pypi.org. Set `supplyChain.verifyRegistry: false` for air-gapped use.
- In GitHub App mode the agent's `search_code` covers only the changed files, because the contents API has no regex search. The Action runs on a full checkout and doesn't have this limit.
- Provenance detection is best effort. Agents that leave no trailer, branch convention or bot author look like humans. Use `--ai <name>` or the MCP `agent` parameter to declare authorship explicitly.

## License

MIT
