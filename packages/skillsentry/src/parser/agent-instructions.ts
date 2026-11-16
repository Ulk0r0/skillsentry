import type { ScanSurface, ScanTarget } from '../types.js';
import { parseFrontmatter } from '../util/text.js';
import path from 'node:path';

/**
 * Agent instruction files: AGENTS.md (the cross-tool convention), CLAUDE.md,
 * .cursorrules and .github/copilot-instructions.md. None of them is executed
 * and none of them declares tools — they are pure prose that coding agents
 * auto-load at repo entry and obey. That makes them the quietest injection
 * surface of the three: the payload's delivery mechanism is obedience.
 *
 * Parsing mirrors parseSkillMd, minus the frontmatter-centric framing: any
 * frontmatter is still scanned (an attacker can use it too), the body is the
 * main surface, and there is always a name to report.
 */
const INSTRUCTION_FILE_NAMES = new Set([
  'agents.md',
  'claude.md',
  '.cursorrules',
  'copilot-instructions.md'
]);

export function isInstructionFile(fileName: string): boolean {
  // Match on the basename, case-insensitively: AGENTS.md is the spec name,
  // but a repo may ship agents.md, and neither spelling changes the risk.
  return INSTRUCTION_FILE_NAMES.has(path.basename(fileName).toLowerCase());
}

export function parseAgentInstructions(filePath: string, raw: string): ScanTarget {
  const fm = parseFrontmatter(raw);
  const base = path.basename(filePath);
  const name = base.replace(/\.(md|markdown|txt)$/i, '').replace(/^\./, '') || base;
  const surfaces: ScanSurface[] = [];

  // Instruction files rarely carry frontmatter, but if one is present it is
  // just as scannable as a SKILL.md's — treat every field as agent-readable.
  for (const [k, v] of Object.entries(fm.data)) {
    const text = Array.isArray(v) ? v.join('; ') : String(v);
    if (text.trim()) surfaces.push({ location: `frontmatter.${k}`, text });
  }
  if (fm.body.trim()) {
    surfaces.push({ location: 'body', text: fm.body });
  }
  return { path: filePath, kind: 'agent-instructions', name, surfaces };
}
