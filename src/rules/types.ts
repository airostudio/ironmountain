import type { Category, Confidence, DiffFile, DiffLine, Provenance, Severity } from "../types.js";

export interface RuleContext {
  file: DiffFile;
  /** Lower-cased file extension without the dot, e.g. "ts". Empty when none. */
  ext: string;
  /** Lower-cased basename, e.g. "package.json". */
  basename: string;
  provenance: Provenance;
  /** All files in the change, for cross-file rules. */
  allFiles: DiffFile[];
}

export interface RuleHit {
  line: number;
  message?: string;
  snippet?: string;
  /** Override the rule's severity for this hit. */
  severity?: Severity;
  confidence?: Confidence;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: Category;
  confidence: Confidence;
  description: string;
  remediation: string;
  cwe?: string[];
  /** Also run on prose/documentation files (md, rst, adoc). Secrets rules always do. */
  scansDocs?: boolean;
  /** Restrict to these extensions / basenames. Omitted = all non-documentation text files. */
  appliesTo?: (ctx: RuleContext) => boolean;
  check(ctx: RuleContext): RuleHit[];
}

export const LANG = {
  js: new Set(["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "vue", "svelte"]),
  py: new Set(["py", "pyw", "pyi"]),
  go: new Set(["go"]),
  java: new Set(["java", "kt", "kts", "scala", "groovy"]),
  rb: new Set(["rb", "erb"]),
  php: new Set(["php", "phtml"]),
  cs: new Set(["cs"]),
  rs: new Set(["rs"]),
  shell: new Set(["sh", "bash", "zsh", "ksh"]),
  yaml: new Set(["yml", "yaml"]),
  tf: new Set(["tf", "hcl"]),
} as const;

export const CODE_EXTS = new Set<string>([
  ...LANG.js,
  ...LANG.py,
  ...LANG.go,
  ...LANG.java,
  ...LANG.rb,
  ...LANG.php,
  ...LANG.cs,
  ...LANG.rs,
  ...LANG.shell,
  "c", "cc", "cpp", "h", "hpp", "swift", "m", "pl", "lua", "ex", "exs", "dart", "sql",
]);

export const DOC_EXTS = new Set(["md", "mdx", "markdown", "rst", "adoc", "asciidoc", "org"]);

export function isCode(ctx: RuleContext): boolean {
  return CODE_EXTS.has(ctx.ext);
}

export function inLang(...langs: (keyof typeof LANG)[]) {
  return (ctx: RuleContext) => langs.some((l) => LANG[l].has(ctx.ext));
}

const COMMENT_ONLY = /^\s*(\/\/|#(?!!)|\*|\/\*|<!--|--\s)/;

export function isCommentLine(content: string): boolean {
  return COMMENT_ONLY.test(content);
}

export interface LineRuleSpec extends Omit<Rule, "check"> {
  /** Any pattern matching flags the line. */
  patterns: RegExp[];
  /** If any of these match the same line, the line is skipped. */
  unless?: RegExp[];
  /** Skip lines that are entirely comments (default true). */
  skipComments?: boolean;
  message?: (line: DiffLine, match: RegExpExecArray) => string;
}

/** Build a rule that scans each added line with a set of regular expressions. */
export function lineRule(spec: LineRuleSpec): Rule {
  const skipComments = spec.skipComments ?? true;
  const { patterns, unless, message, skipComments: _s, ...meta } = spec;
  return {
    ...meta,
    check(ctx) {
      const hits: RuleHit[] = [];
      for (const l of ctx.file.added) {
        if (l.content.length > 4000) continue; // minified / generated
        if (skipComments && isCommentLine(l.content)) continue;
        for (const re of patterns) {
          re.lastIndex = 0;
          const m = re.exec(l.content);
          if (!m) continue;
          if (unless?.some((u) => ((u.lastIndex = 0), u.test(l.content)))) break;
          hits.push({ line: l.line, message: message?.(l, m), snippet: l.content.trim().slice(0, 240) });
          break;
        }
      }
      return hits;
    },
  };
}
