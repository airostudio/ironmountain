import { lineRule, type Rule } from "./types.js";

// Placeholders an LLM typically writes into examples; never flag these.
const PLACEHOLDER =
  /(example|sample|dummy|placeholder|changeme|change_me|your[_-]?|xxx+|\*\*\*+|<[^>]+>|\$\{|\{\{|process\.env|os\.environ|getenv|env\(|ENV\[|secrets\.|redacted|fake|test[_-]?(key|token|secret)|not[_-]?a[_-]?real)/i;

const secretRule = (
  id: string,
  title: string,
  pattern: RegExp,
  severity: Rule["severity"] = "critical",
): Rule =>
  lineRule({
    id,
    title,
    severity,
    category: "secrets",
    confidence: "high",
    cwe: ["CWE-798"],
    description: `${title} committed to source control.`,
    remediation:
      "Revoke and rotate this credential immediately, remove it from git history, and load it from a secret manager or environment variable instead.",
    patterns: [pattern],
    skipComments: false,
  });

export const secretRules: Rule[] = [
  secretRule("secrets/aws-access-key", "AWS access key ID", /\b(AKIA|ASIA)[0-9A-Z]{16}\b/),
  secretRule(
    "secrets/aws-secret-key",
    "AWS secret access key",
    /aws.{0,20}(secret|private).{0,20}['"][A-Za-z0-9/+=]{40}['"]/i,
  ),
  secretRule("secrets/github-token", "GitHub token", /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/),
  secretRule("secrets/anthropic-key", "Anthropic API key", /\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{20,}/),
  secretRule("secrets/openai-key", "OpenAI API key", /\bsk-(proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}/),
  secretRule("secrets/google-api-key", "Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/, "high"),
  secretRule("secrets/slack-token", "Slack token", /\bxox[abposr]-[0-9A-Za-z-]{10,}/),
  secretRule("secrets/slack-webhook", "Slack webhook URL", /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, "high"),
  secretRule("secrets/stripe-key", "Stripe live secret key", /\b(sk|rk)_live_[0-9a-zA-Z]{20,}/),
  secretRule("secrets/twilio-key", "Twilio API key", /\bSK[0-9a-fA-F]{32}\b/, "high"),
  secretRule("secrets/sendgrid-key", "SendGrid API key", /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/),
  secretRule("secrets/npm-token", "npm access token", /\bnpm_[A-Za-z0-9]{36}\b/),
  secretRule("secrets/pypi-token", "PyPI upload token", /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/),
  secretRule("secrets/huggingface-token", "Hugging Face token", /\bhf_[A-Za-z]{34}\b/, "high"),
  secretRule(
    "secrets/private-key",
    "Private key",
    /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/,
  ),
  lineRule({
    id: "secrets/connection-string",
    title: "Credentials embedded in connection string",
    severity: "high",
    category: "secrets",
    confidence: "medium",
    cwe: ["CWE-798"],
    description: "A database or broker URL contains an inline username and password.",
    remediation: "Move the password to a secret store / environment variable and build the URL at runtime.",
    patterns: [/\b(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|rediss|amqps?|mssql|sqlserver):\/\/[^:\s/'"]+:[^@\s'"]{3,}@/i],
    unless: [PLACEHOLDER, /:(password|pass|pwd|secret)@/i],
    skipComments: false,
  }),
  lineRule({
    id: "secrets/jwt-literal",
    title: "Hardcoded JSON Web Token",
    severity: "medium",
    category: "secrets",
    confidence: "medium",
    cwe: ["CWE-798"],
    description: "A signed JWT is embedded in source. Tokens often grant real access until they expire.",
    remediation: "Remove the token and obtain it at runtime.",
    patterns: [/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
    skipComments: false,
  }),
  lineRule({
    id: "secrets/hardcoded-credential",
    title: "Hardcoded password or API secret",
    severity: "high",
    category: "secrets",
    confidence: "medium",
    cwe: ["CWE-798", "CWE-259"],
    description: "A variable whose name implies a credential is assigned a string literal.",
    remediation: "Read the value from configuration or a secret manager; never commit credentials.",
    patterns: [
      /\b[\w.-]*(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b["']?\s*[:=]=?\s*["'][^"'\s]{8,}["']/i,
    ],
    unless: [PLACEHOLDER, /\b(type|label|name|field|placeholder|hint|message|msg|error|description|title|header|key_name|env_var)\b\s*[:=]/i, /==\s*["']/],
  }),
];
