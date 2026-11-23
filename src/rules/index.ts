import { aiIntegrityRules } from "./ai-integrity.js";
import { ciInfraRules } from "./ci-infra.js";
import { cryptoRules } from "./crypto.js";
import { injectionRules } from "./injection.js";
import { secretRules } from "./secrets.js";
import { supplyChainRules } from "./supply-chain.js";
import type { Rule } from "./types.js";
import { webRules } from "./web.js";

export const ALL_RULES: Rule[] = [
  ...secretRules,
  ...injectionRules,
  ...cryptoRules,
  ...webRules,
  ...ciInfraRules,
  ...supplyChainRules,
  ...aiIntegrityRules,
];

const ids = new Set<string>();
for (const r of ALL_RULES) {
  if (ids.has(r.id)) throw new Error(`duplicate rule id ${r.id}`);
  ids.add(r.id);
}

export function getRule(id: string): Rule | undefined {
  return ALL_RULES.find((r) => r.id === id);
}

export type { Rule } from "./types.js";
