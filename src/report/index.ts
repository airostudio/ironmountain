import type { Report } from "../types.js";
import { toHtml } from "./html.js";
import { toMarkdown } from "./markdown.js";
import { toSarif } from "./sarif.js";
import { toTerminal } from "./terminal.js";

export type Format = "terminal" | "markdown" | "json" | "sarif" | "html";
export const FORMATS: Format[] = ["terminal", "markdown", "json", "sarif", "html"];

export function render(report: Report, format: Format): string {
  switch (format) {
    case "terminal":
      return toTerminal(report);
    case "markdown":
      return toMarkdown(report);
    case "json":
      return JSON.stringify(report, null, 2);
    case "sarif":
      return JSON.stringify(toSarif(report), null, 2);
    case "html":
      return toHtml(report);
  }
}

export { toHtml, toMarkdown, toSarif, toTerminal };
