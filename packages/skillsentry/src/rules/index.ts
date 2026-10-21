import type { TargetKind } from '../types.js';
import type { Rule } from './rule.js';
import { hiddenInstructions } from './hidden-instructions.js';
import { exfiltration } from './exfiltration.js';
import { credentialAccess } from './credential-access.js';
import { destructiveCommands } from './destructive-commands.js';
import { obfuscation } from './obfuscation.js';
import { crossToolShadowing } from './cross-tool-shadowing.js';
import { dataCollection } from './data-collection.js';
import { insecureMcpConfig } from './insecure-mcp-config.js';
import { metadataMismatch } from './metadata-mismatch.js';

/**
 * The static rule registry. Every rule is deterministic and offline — the
 * open-weight model layer is additive, never required for a scan to run.
 */
export const ALL_RULES: Rule[] = [
  hiddenInstructions,     // SS-001
  exfiltration,           // SS-002
  credentialAccess,       // SS-003
  destructiveCommands,    // SS-004
  obfuscation,            // SS-005
  crossToolShadowing,     // SS-006
  dataCollection,         // SS-007
  insecureMcpConfig,      // SS-008
  metadataMismatch        // SS-009
];

export const RULES_BY_ID: ReadonlyMap<string, Rule> = new Map(ALL_RULES.map((r) => [r.id, r]));

export function rulesFor(kind: TargetKind): Rule[] {
  return ALL_RULES.filter((r) => r.appliesTo.includes(kind));
}

export type { Rule, RawMatch } from './rule.js';
export { hiddenInstructions, exfiltration, credentialAccess, destructiveCommands, obfuscation, crossToolShadowing, dataCollection, insecureMcpConfig, metadataMismatch };
