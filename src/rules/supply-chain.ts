import type { DiffFile } from "../types.js";
import { KNOWN_MALICIOUS_NPM, KNOWN_MALICIOUS_PYPI, POPULAR_NPM, POPULAR_PYPI } from "./popular-packages.js";
import { lineRule, type Rule, type RuleHit } from "./types.js";

export type Ecosystem = "npm" | "pypi";

export interface DependencyAddition {
  ecosystem: Ecosystem;
  name: string;
  spec: string;
  file: string;
  line: number;
}

const PKG_JSON_NON_DEP_KEYS = new Set([
  "name", "version", "description", "main", "module", "types", "typings", "license", "author", "homepage",
  "type", "private", "packageManager", "browser", "bin", "exports", "files", "repository", "bugs", "url",
  "email", "directory", "node", "npm", "pnpm", "yarn", "default", "import", "require", "workspaces",
  "test", "build", "start", "dev", "lint", "format", "typecheck", "prepare", "preinstall", "install",
  "postinstall", "prepublishOnly", "release", "sideEffects", "funding", "access", "registry", "tag",
]);

const VERSIONISH = /^(\^|~|>=?|<=?|=|\*|latest|next|\d|x\b|workspace:|npm:|git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|portal:|catalog:)/;

/** Pull newly-added dependency declarations out of manifest diffs. */
export function extractDependencies(files: DiffFile[]): DependencyAddition[] {
  const deps: DependencyAddition[] = [];
  for (const f of files) {
    const base = f.path.split("/").pop()!.toLowerCase();
    if (base === "package.json") {
      for (const l of f.added) {
        const m = /^\s*"((?:@[\w.-]+\/)?[\w.-]+)"\s*:\s*"([^"]*)"\s*,?\s*$/.exec(l.content);
        if (!m || PKG_JSON_NON_DEP_KEYS.has(m[1]!) || !VERSIONISH.test(m[2]!)) continue;
        deps.push({ ecosystem: "npm", name: m[1]!, spec: m[2]!, file: f.path, line: l.line });
      }
    } else if (/^requirements.*\.(txt|in)$|^constraints.*\.txt$/.test(base)) {
      for (const l of f.added) {
        const t = l.content.trim();
        if (!t || t.startsWith("#") || t.startsWith("-")) continue;
        const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$/.exec(t);
        if (m) deps.push({ ecosystem: "pypi", name: m[1]!.toLowerCase(), spec: m[3]!.trim(), file: f.path, line: l.line });
      }
    } else if (base === "pyproject.toml" || base === "pipfile") {
      for (const l of f.added) {
        const m =
          /^\s*"([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*([<>=~!][^"]*)?(;[^"]*)?"\s*,?\s*$/.exec(l.content) ??
          /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*("[^"]*"|\{[^}]*\})\s*$/.exec(l.content);
        if (!m) continue;
        const name = m[1]!.toLowerCase();
        if (["name", "version", "description", "python", "requires-python", "readme", "license", "build-backend", "url", "verify_ssl"].includes(name)) continue;
        deps.push({ ecosystem: "pypi", name, spec: (m[3] ?? m[2] ?? "").replace(/"/g, ""), file: f.path, line: l.line });
      }
    }
  }
  return deps;
}

/** Optimal string alignment distance (Damerau-Levenshtein with adjacent transpositions). */
export function editDistance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, d[i - 2]![j - 2]! + 1);
      d[i]![j] = v;
    }
  }
  return d[a.length]![b.length]!;
}

const normalize = (n: string) => n.toLowerCase().replace(/[-_.]+/g, "");

export function findTyposquatTarget(name: string, ecosystem: Ecosystem): string | null {
  const popular = ecosystem === "npm" ? POPULAR_NPM : POPULAR_PYPI;
  const lower = name.toLowerCase();
  if (popular.includes(lower)) return null;
  const bare = lower.replace(/^@[\w.-]+\//, "");
  for (const p of popular) {
    if (normalize(p) === normalize(bare) && p !== lower) return p; // separator confusion: python_dateutil vs python-dateutil
    const max = p.length >= 8 ? 2 : 1;
    if (p.length >= 4 && Math.abs(p.length - bare.length) <= max && editDistance(bare, p) <= max && bare !== p) return p;
    // Suffix/prefix squats: lodash-js, node-axios, axios.js
    if (p.length >= 4 && [`${p}js`, `${p}.js`, `${p}-js`, `node-${p}`, `${p}-node`, `py${p}`, `python-${p}`, `${p}2`, `${p}-dev`].includes(bare)) return p;
  }
  return null;
}

const dependencyRisk: Rule = {
  id: "supply-chain/suspicious-dependency",
  title: "Suspicious new dependency",
  severity: "high",
  category: "supply-chain",
  confidence: "medium",
  cwe: ["CWE-829", "CWE-1357"],
  description:
    "A newly added dependency matches a known-malicious name, closely resembles a popular package (typosquat), or is pulled from an unpinned git/URL source. AI assistants also invent package names that attackers then register (\"slopsquatting\").",
  remediation: "Confirm the exact package name on the registry, check its maintainers, age and download counts, and pin an exact version with a lockfile.",
  check(ctx) {
    const hits: RuleHit[] = [];
    for (const dep of extractDependencies([ctx.file])) {
      const malicious = dep.ecosystem === "npm" ? KNOWN_MALICIOUS_NPM : KNOWN_MALICIOUS_PYPI;
      if (malicious.has(dep.name.toLowerCase())) {
        hits.push({ line: dep.line, severity: "critical", confidence: "high", message: `\`${dep.name}\` is a known malicious package name.` });
        continue;
      }
      const target = findTyposquatTarget(dep.name, dep.ecosystem);
      if (target) {
        hits.push({ line: dep.line, message: `\`${dep.name}\` looks like a typosquat of the popular package \`${target}\`.` });
        continue;
      }
      if (/^(git\+|git:|github:|gitlab:|bitbucket:|https?:)/.test(dep.spec) && !/#[0-9a-f]{40}$/.test(dep.spec)) {
        hits.push({ line: dep.line, severity: "medium", message: `\`${dep.name}\` is installed from an unpinned git/URL source (${dep.spec}).` });
        continue;
      }
      if (dep.spec === "*" || dep.spec === "latest" || dep.spec === "x") {
        hits.push({ line: dep.line, severity: "low", confidence: "high", message: `\`${dep.name}\` uses an unbounded version (${dep.spec}).` });
      }
    }
    return hits;
  },
};

export const supplyChainRules: Rule[] = [
  dependencyRisk,
  lineRule({
    id: "supply-chain/install-script",
    title: "Package lifecycle install script added",
    severity: "medium",
    category: "supply-chain",
    confidence: "medium",
    cwe: ["CWE-829"],
    description: "preinstall/install/postinstall scripts run automatically on every developer machine and CI runner that installs the package; they are the most common npm malware vector.",
    remediation: "Avoid install hooks; if unavoidable, keep them minimal and never fetch or execute remote content.",
    appliesTo: (ctx) => ctx.basename === "package.json",
    patterns: [/^\s*"(preinstall|install|postinstall|preuninstall)"\s*:\s*"/],
    message: (l) =>
      /curl|wget|https?:\/\/|node\s+-e|eval|base64|\|\s*sh/.test(l.content)
        ? "Install script downloads or evaluates code at install time."
        : "New install-time lifecycle script.",
  }),
  lineRule({
    id: "supply-chain/dependency-confusion",
    title: "Extra package index or trusted host configured",
    severity: "high",
    category: "supply-chain",
    confidence: "medium",
    cwe: ["CWE-427"],
    description: "--extra-index-url merges a second index with PyPI, so a public package with the same name as an internal one can win (dependency confusion). --trusted-host disables TLS checks.",
    remediation: "Use a single private index that proxies PyPI, or pin with --require-hashes.",
    appliesTo: (ctx) => /requirements|constraints|pip\.conf|pip\.ini|\.npmrc|\.yarnrc|pyproject|Dockerfile/i.test(ctx.file.path) || ctx.ext === "sh",
    patterns: [/--extra-index-url\b|extra-index-url\s*=/, /--trusted-host\b|trusted-host\s*=/, /--index-url\s+http:\/\//, /^\s*registry\s*=\s*http:\/\//],
    skipComments: false,
  }),
  lineRule({
    id: "supply-chain/lockfile-integrity",
    title: "Lockfile resolves to a non-registry or insecure URL",
    severity: "high",
    category: "supply-chain",
    confidence: "medium",
    cwe: ["CWE-494"],
    description: "A lockfile entry was changed to resolve from an unexpected host or over HTTP, a sign of lockfile poisoning.",
    remediation: "Regenerate the lockfile from the official registry and review the diff.",
    appliesTo: (ctx) => ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"].includes(ctx.basename),
    patterns: [/"?resolved"?\s*[:=]?\s*"?http:\/\//, /"?resolved"?\s*[:=]?\s*"?https:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com|npm\.pkg\.github\.com|codeload\.github\.com)/],
    skipComments: false,
  }),
];

export interface RegistryResult {
  dep: DependencyAddition;
  status: "missing" | "new" | "ok" | "unknown";
  createdAt?: string;
}

/**
 * Check that each newly added dependency exists on its public registry.
 * A package that does not exist is the hallmark of an AI hallucination, and an
 * attacker can register that name at any time.
 */
export async function verifyRegistry(
  deps: DependencyAddition[],
  opts: { timeoutMs?: number; newPackageDays?: number; fetchImpl?: typeof fetch } = {},
): Promise<RegistryResult[]> {
  const doFetch = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 6000;
  const newDays = opts.newPackageDays ?? 30;
  const unique = deps.filter((d) => !/^(git|github|gitlab|bitbucket|https?|file|link|workspace|portal|npm):/.test(d.spec));

  const one = async (dep: DependencyAddition): Promise<RegistryResult> => {
    const url =
      dep.ecosystem === "npm"
        ? `https://registry.npmjs.org/${dep.name.replace("/", "%2F")}`
        : `https://pypi.org/pypi/${encodeURIComponent(dep.name)}/json`;
    try {
      const res = await doFetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: "application/json" } });
      if (res.status === 404) return { dep, status: "missing" };
      if (!res.ok) return { dep, status: "unknown" };
      const body = (await res.json()) as Record<string, unknown>;
      let created: string | undefined;
      if (dep.ecosystem === "npm") {
        created = (body.time as Record<string, string> | undefined)?.created;
      } else {
        const releases = (body.releases ?? {}) as Record<string, { upload_time_iso_8601?: string }[]>;
        const times = Object.values(releases).flat().map((r) => r.upload_time_iso_8601).filter(Boolean) as string[];
        created = times.sort()[0];
      }
      if (created && Date.now() - Date.parse(created) < newDays * 86_400_000) return { dep, status: "new", createdAt: created };
      return { dep, status: "ok", ...(created ? { createdAt: created } : {}) };
    } catch {
      return { dep, status: "unknown" };
    }
  };

  const results: RegistryResult[] = [];
  for (let i = 0; i < unique.length; i += 6) results.push(...(await Promise.all(unique.slice(i, i + 6).map(one))));
  return results;
}
