// Prints the rule catalogue as a Markdown table for the README.
import { ALL_RULES } from "../src/rules/index.js";

const rows = ALL_RULES.map((r) => `| \`${r.id}\` | ${r.severity} | ${r.title} |${(r.cwe ?? []).join(", ")}|`);
console.log(["| Rule | Default severity | Detects | CWE |", "|---|---|---|---|", ...rows].join("\n"));
