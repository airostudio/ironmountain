import { parseConfig } from "../src/config.js";
import { fileAsAdded } from "../src/diff.js";
import { runRules } from "../src/engine.js";
import { HUMAN_PROVENANCE } from "../src/provenance.js";
import type { DiffFile, Finding } from "../src/types.js";

export const config = parseConfig({});

export function scan(path: string, code: string): Finding[] {
  return runRules([fileAsAdded(path, code)], HUMAN_PROVENANCE, config);
}

export function ids(path: string, code: string): string[] {
  return scan(path, code).map((f) => f.ruleId);
}

export function scanFiles(files: DiffFile[]): Finding[] {
  return runRules(files, HUMAN_PROVENANCE, config);
}

/** Fake credentials are assembled at runtime so this repository never contains a matchable secret. */
export const fake = {
  aws: "AKIA" + "Z7XQ4MLD2PRT8WHN",
  github: "ghp" + "_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
  stripe: "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
  anthropic: "sk-ant-" + "api03-" + "q".repeat(40),
  slack: "xox" + "b-" + "123456789012-abcdefghijklmnop",
  pem: "-----BEGIN " + "RSA PRIVATE KEY-----",
};
