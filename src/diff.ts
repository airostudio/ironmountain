import type { DiffFile, Hunk } from "./types.js";

const HUNK_RE = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$/;

function stripPrefix(p: string): string {
  if (p === "/dev/null") return p;
  // git quotes paths with unusual characters: "a/some path"
  if (p.startsWith('"') && p.endsWith('"')) p = JSON.parse(p) as string;
  return p.replace(/^[ab]\//, "");
}

/**
 * Parse a unified diff (as produced by `git diff` or the GitHub API) into
 * per-file added/removed line lists with accurate new-file line numbers.
 */
export function parseUnifiedDiff(text: string): DiffFile[] {
  const files: DiffFile[] = [];
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  let cur: DiffFile | null = null;
  let oldLine = 0;
  let newLine = 0;
  let inHunk = false;
  let oldRemaining = 0;
  let newRemaining = 0;

  const startFile = (path: string, oldPath?: string): DiffFile => {
    const f: DiffFile = { path, status: "modified", isBinary: false, hunks: [], added: [], removed: [] };
    if (oldPath && oldPath !== path) f.oldPath = oldPath;
    files.push(f);
    return f;
  };

  for (const raw of lines) {
    if (raw.startsWith("diff --git ")) {
      inHunk = false;
      const m = /^diff --git (\S+|"[^"]+") (\S+|"[^"]+")$/.exec(raw);
      const a = m ? stripPrefix(m[1]!) : "";
      const b = m ? stripPrefix(m[2]!) : "";
      cur = startFile(b, a);
      continue;
    }

    if (!inHunk || (oldRemaining <= 0 && newRemaining <= 0)) {
      inHunk = false;
      if (raw.startsWith("--- ")) {
        const p = stripPrefix(raw.slice(4).split("\t")[0]!);
        // Plain unified diffs (no "diff --git" header) start a file here.
        if (!cur || cur.hunks.length > 0) cur = startFile(p === "/dev/null" ? "" : p);
        if (p === "/dev/null") cur.status = "added";
        else if (!cur.oldPath && cur.path !== p && cur.path) cur.oldPath = p;
        continue;
      }
      if (raw.startsWith("+++ ")) {
        const p = stripPrefix(raw.slice(4).split("\t")[0]!);
        if (!cur) cur = startFile(p);
        if (p === "/dev/null") cur.status = "deleted";
        else cur.path = p;
        continue;
      }
      if (cur) {
        if (raw.startsWith("new file mode")) {
          cur.status = "added";
          cur.newMode = raw.split(" ").pop();
          continue;
        }
        if (raw.startsWith("deleted file mode")) {
          cur.status = "deleted";
          continue;
        }
        if (raw.startsWith("new mode ")) {
          cur.newMode = raw.slice("new mode ".length).trim();
          continue;
        }
        if (raw.startsWith("rename from ")) {
          cur.oldPath = raw.slice("rename from ".length);
          cur.status = "renamed";
          continue;
        }
        if (raw.startsWith("rename to ")) {
          cur.path = raw.slice("rename to ".length);
          continue;
        }
        if (raw.startsWith("Binary files ") || raw.startsWith("GIT binary patch")) {
          cur.isBinary = true;
          continue;
        }
      }
    }

    const hm = HUNK_RE.exec(raw);
    if (hm && cur) {
      const hunk: Hunk = {
        oldStart: Number(hm[1]),
        oldLines: hm[2] === undefined ? 1 : Number(hm[2]),
        newStart: Number(hm[3]),
        newLines: hm[4] === undefined ? 1 : Number(hm[4]),
        header: (hm[5] ?? "").trim(),
      };
      cur.hunks.push(hunk);
      oldLine = hunk.oldStart;
      newLine = hunk.newStart;
      oldRemaining = hunk.oldLines;
      newRemaining = hunk.newLines;
      inHunk = true;
      continue;
    }

    if (!cur || !inHunk) continue;
    if (raw.startsWith("\\")) continue; // "\ No newline at end of file"

    const tag = raw[0];
    const body = raw.slice(1);
    if (tag === "+") {
      cur.added.push({ line: newLine++, content: body });
      newRemaining--;
    } else if (tag === "-") {
      cur.removed.push({ line: oldLine++, content: body });
      oldRemaining--;
    } else if (tag === " " || raw === "") {
      oldLine++;
      newLine++;
      oldRemaining--;
      newRemaining--;
    }
  }

  for (const f of files) {
    if (!f.oldPath) delete f.oldPath;
    if (f.status === "deleted" && f.oldPath && !f.path) f.path = f.oldPath;
  }
  return files.filter((f) => f.path !== "");
}

/** Build a synthetic "everything is added" diff for full-file scans. */
export function fileAsAdded(path: string, content: string): DiffFile {
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return {
    path,
    status: "added",
    isBinary: content.includes("\u0000"),
    hunks: [{ oldStart: 0, oldLines: 0, newStart: 1, newLines: lines.length, header: "" }],
    added: lines.map((content, i) => ({ line: i + 1, content })),
    removed: [],
  };
}
