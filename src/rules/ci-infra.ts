import { inLang, lineRule, type Rule, type RuleContext } from "./types.js";

const isWorkflow = (ctx: RuleContext) => /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(ctx.file.path) || /(^|\/)action\.ya?ml$/i.test(ctx.file.path);
const isDockerfile = (ctx: RuleContext) => /(^|\/)(Dockerfile|Containerfile)(\.[\w-]+)?$/i.test(ctx.file.path) || ctx.ext === "dockerfile";
const isK8s = (ctx: RuleContext) => ["yml", "yaml"].includes(ctx.ext) && !isWorkflow(ctx);

const UNTRUSTED_GH_CONTEXT =
  /\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|pages\.[^}]*\.page_name|commits\.[^}]*\.(message|author\.(email|name))|head_commit\.(message|author\.(email|name)))|github\.head_ref)\s*\}\}/;

export const ciInfraRules: Rule[] = [
  {
    id: "ci/script-injection",
    title: "GitHub Actions script injection",
    severity: "high",
    category: "ci",
    confidence: "high",
    cwe: ["CWE-78", "CWE-94"],
    description:
      "Attacker-controlled event fields (issue titles, PR bodies, branch names, commit messages) are expanded directly into a shell script, giving anyone who can open an issue or PR code execution in your CI with its secrets.",
    remediation: "Pass the value through an environment variable (env: TITLE: ${{ github.event.issue.title }}) and reference it as \"$TITLE\" in the script.",
    appliesTo: isWorkflow,
    check(ctx) {
      return ctx.file.added
        .filter((l) => UNTRUSTED_GH_CONTEXT.test(l.content))
        // Safe: assigning to an env var / with: input (but not run:)
        .filter((l) => !/^\s*-?\s*(?!run\b)[\w.-]+\s*:\s*["']?\$\{\{[^}]*\}\}["']?\s*$/.test(l.content) && !/^\s*if\s*:/.test(l.content))
        .map((l) => ({ line: l.line, snippet: l.content.trim() }));
    },
  },
  {
    id: "ci/pull-request-target-checkout",
    title: "pull_request_target workflow checks out untrusted PR code",
    severity: "critical",
    category: "ci",
    confidence: "high",
    cwe: ["CWE-829"],
    description:
      "pull_request_target runs with a write token and secrets. Checking out and building the PR head lets any fork author run code with those privileges (\"pwn request\").",
    remediation: "Use the pull_request trigger for untrusted code, or split into an unprivileged build job and a privileged job that only consumes artifacts.",
    appliesTo: isWorkflow,
    check(ctx) {
      const prt = ctx.file.added.find((l) => /\bpull_request_target\b/.test(l.content));
      const checkout = ctx.file.added.find((l) =>
        /ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)|refs\/pull\/.*\/merge|github\.event\.pull_request\.merge_commit_sha/.test(l.content),
      );
      if (prt && checkout) return [{ line: checkout.line, snippet: checkout.content.trim() }];
      if (prt) return [{ line: prt.line, severity: "medium", confidence: "low", message: "pull_request_target grants secrets and a write token; make sure no step runs PR-controlled code." }];
      return [];
    },
  },
  lineRule({
    id: "ci/excessive-permissions",
    title: "Workflow requests write-all permissions",
    severity: "medium",
    category: "ci",
    confidence: "high",
    cwe: ["CWE-250"],
    description: "A broadly scoped GITHUB_TOKEN magnifies the impact of any compromised step.",
    remediation: "Declare least-privilege permissions per job (e.g. contents: read).",
    appliesTo: isWorkflow,
    patterns: [/^\s*permissions\s*:\s*write-all\b/],
  }),
  lineRule({
    id: "ci/unpinned-action",
    title: "Third-party action pinned to a mutable ref",
    severity: "medium",
    category: "supply-chain",
    confidence: "high",
    cwe: ["CWE-829"],
    description: "Referencing an action by branch lets its owner (or anyone who compromises it) change the code your workflow runs, as in the tj-actions/changed-files incident.",
    remediation: "Pin third-party actions to a full 40-character commit SHA.",
    appliesTo: isWorkflow,
    patterns: [/^\s*-?\s*uses\s*:\s*(?!actions\/|github\/|\.\/|docker:\/\/)[\w.-]+\/[\w./-]+@(main|master|dev|develop|latest|HEAD|v?\d+(\.\d+)?)\s*$/],
  }),
  lineRule({
    id: "ci/secret-exposure",
    title: "Secret printed or exported in CI",
    severity: "high",
    category: "ci",
    confidence: "medium",
    cwe: ["CWE-532"],
    description: "Echoing secrets or enabling insecure commands can leak credentials into logs or allow environment injection.",
    remediation: "Never print secrets; pass them via env and let the runner mask them.",
    appliesTo: isWorkflow,
    patterns: [/\b(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\./, /ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*["']?true/i, /\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}/],
  }),
  lineRule({
    id: "infra/curl-pipe-shell",
    title: "Remote script piped directly into a shell",
    severity: "high",
    category: "supply-chain",
    confidence: "high",
    cwe: ["CWE-494"],
    description: "curl | sh executes whatever the server (or a network attacker) returns, with no integrity check.",
    remediation: "Download to a file, verify a pinned checksum or signature, then execute.",
    patterns: [/\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(-\w+\s+)*(ba|z|k|da)?sh\b/, /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b/, /\biex\s*\(\s*(New-Object\s+Net\.WebClient|iwr|Invoke-WebRequest)/i],
    skipComments: true,
  }),
  lineRule({
    id: "infra/docker-root-or-latest",
    title: "Container runs as root or uses a floating base image",
    severity: "low",
    category: "infra",
    confidence: "medium",
    cwe: ["CWE-250"],
    description: "Running as root widens container-escape impact; :latest makes builds non-reproducible and silently pulls new code.",
    remediation: "Pin base images by digest and add a non-root USER.",
    appliesTo: isDockerfile,
    patterns: [/^\s*USER\s+(root|0)\s*$/i, /^\s*FROM\s+[^\s:@]+(:latest)?(\s+AS\s+\w+)?\s*$/i],
    unless: [/^\s*FROM\s+scratch\b/i, /^\s*FROM\s+\w+\s*$/i],
  }),
  lineRule({
    id: "infra/docker-secret-in-image",
    title: "Secret baked into container image",
    severity: "high",
    category: "secrets",
    confidence: "medium",
    cwe: ["CWE-538"],
    description: "ENV/ARG values and COPY'd credential files persist in image layers and are readable by anyone who can pull the image.",
    remediation: "Use BuildKit secrets (RUN --mount=type=secret) or runtime injection.",
    appliesTo: isDockerfile,
    patterns: [/^\s*(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)\w*[\s=]+\S+/i, /^\s*(COPY|ADD)\s+[^\n]*(\.env|id_rsa|\.pem|credentials|\.npmrc|\.pypirc)\b/i],
  }),
  lineRule({
    id: "infra/k8s-privileged",
    title: "Privileged or host-level container settings",
    severity: "high",
    category: "infra",
    confidence: "high",
    cwe: ["CWE-250"],
    description: "privileged / hostNetwork / hostPID / hostPath / docker.sock mounts give a container effective root on the node.",
    remediation: "Remove the setting; use specific capabilities and a restricted Pod Security Standard.",
    appliesTo: (ctx) => isK8s(ctx) || /docker-compose|compose\.ya?ml/i.test(ctx.file.path),
    patterns: [/^\s*privileged\s*:\s*true/, /^\s*host(Network|PID|IPC)\s*:\s*true/, /^\s*allowPrivilegeEscalation\s*:\s*true/, /\/var\/run\/docker\.sock/, /^\s*-\s*(SYS_ADMIN|ALL)\s*$/, /^\s*runAsUser\s*:\s*0\s*$/],
  }),
  lineRule({
    id: "infra/public-exposure",
    title: "Cloud resource exposed to the internet",
    severity: "high",
    category: "infra",
    confidence: "medium",
    cwe: ["CWE-284"],
    description: "Public buckets, publicly accessible databases and 0.0.0.0/0 ingress on admin ports are a leading cause of breaches.",
    remediation: "Restrict CIDR ranges, keep storage private and front services with authenticated gateways.",
    appliesTo: inLang("tf"),
    patterns: [
      /acl\s*=\s*"(public-read|public-read-write|authenticated-read)"/,
      /publicly_accessible\s*=\s*true/,
      /block_public_(acls|policy)\s*=\s*false/,
      /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/,
      /"Principal"\s*:\s*"\*"|principals\s*\{\s*type\s*=\s*"\*"/,
      /encrypted\s*=\s*false|storage_encrypted\s*=\s*false/,
    ],
  }),
  lineRule({
    id: "infra/iam-wildcard",
    title: "IAM policy grants wildcard actions",
    severity: "high",
    category: "infra",
    confidence: "medium",
    cwe: ["CWE-269"],
    description: "Action \"*\" on Resource \"*\" grants full account control to whoever holds the role.",
    remediation: "Grant only the specific actions and resources required.",
    appliesTo: (ctx) => inLang("tf")(ctx) || ctx.ext === "json",
    patterns: [/"?Action"?\s*[:=]\s*\[?\s*"\*"/, /actions\s*=\s*\[\s*"\*"\s*\]/, /"?Action"?\s*[:=]\s*\[?\s*"(iam|s3|ec2|kms):\*"/],
  }),
];
