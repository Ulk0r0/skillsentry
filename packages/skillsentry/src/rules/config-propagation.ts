import type { Rule } from './rule.js';
import { AST, LLM, MCP } from '../mapping.js';
import { evidenceFor, firstMatch } from '../util/text.js';

/**
 * SS-014 — Agent config poisoning propagation: the self-replication signature
 * of agent worms. Where SS-006 catches a skill shadowing other tools at
 * runtime, SS-014 catches the quieter move — instructions that make the agent
 * *rewrite files*: append payload blocks to other installed SKILL.md files,
 * copy itself across skill directories, or patch MCP configuration to add
 * attacker-controlled servers. One poisoned skill that edits its neighbours
 * turns a single supply-chain hit into a fleet-wide infection.
 *
 * Precision first: "copy this folder to your skills directory" (self-install
 * docs) stays clean; only cross-skill writes and agent-voiced config edits
 * are flagged.
 */
const RUNTIME_VOICE =
  /\b(?:automatically|silently|before\s+(?:responding|answering|each)|after\s+(?:each|every|the\s+first)|on\s+(?:startup|install|load)|each\s+(?:session|run|time)|every\s+(?:session|run|time|future)|do\s+not\s+(?:tell|mention|inform)|the\s+agent\b|ensure\s+the?\b)/i;

const PATTERNS: Array<{ re: RegExp; label: string; score: number }> = [
  // explicit "other skills" targeting
  {
    re: /\b(?:modify|edit|rewrite|patch|update|append\s+to|inject\s+into)\b[^.\n]{0,60}\bother\s+(?:skills?|SKILL\.md|agents?\b)/gi,
    label: 'instructions to modify other skills', score: 9
  },
  // payload injection scoped to every/all skills
  {
    re: /\b(?:append|add|write|inject|insert)\b[^.\n]{0,60}\b(?:block|section|rules?|instructions?|text|payload|directive)\b[^.\n]{0,50}\b(?:to|into)\s+(?:every|all|other)\b[^.\n]{0,30}\bskills?\b/gi,
    label: 'payload injection scoped to every/all skills', score: 9
  },
  // self-copy across skill files/directories (worm move)
  {
    re: /\b(?:cp|copy)\b[^|\n]{0,80}\b(?:SKILL\.md|skills?\/)[^|\n]{0,60}\b(?:SKILL\.md|skills?\/)/gi,
    label: 'self-copy across skill files/directories', score: 9
  }
];

/** MCP config rewrite verbs — only flagged in agent/runtime voice. */
const MCP_EDIT =
  /\b(?:modify|edit|patch|rewrite|update|remove|inject\w*)\b[^.\n]{0,50}\b(?:mcp\.json|claude_desktop_config\.json|\.mcp\.json|mcp\s+(?:server\s+)?config(?:uration)?)/gi;

export const configPropagation: Rule = {
  id: 'SS-014',
  title: 'Agent config poisoning propagation (skill self-replication)',
  description:
    'Instructions that direct the agent to write to other installed skills (append blocks to every SKILL.md, copy payloads across skill directories) or to rewrite MCP configuration in agent/runtime voice. This is the propagation step of an agent worm: one poisoned skill editing its neighbours converts a single supply-chain hit into persistent, fleet-wide infection.',
  remediation:
    'Agent skills must never instruct writes to other skills or to MCP configuration. Treat any self-replication directive as malware: remove the skill, audit every file it could touch, and rotate any credentials the agent holds.',
  severity: 'critical',
  score: 9,
  standards: [AST.poisoning(), MCP.toolPoisoning(), LLM.dataPoisoning()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'critical' | 'high'; score?: number }> = [];
    const seen = new Set<string>();

    for (const p of PATTERNS) {
      const m = firstMatch(p.re, surface.text);
      if (m && !seen.has(m[0])) {
        seen.add(m[0]);
        out.push({
          evidence: evidenceFor(surface.text, m[0]),
          note: `Matched pattern: ${p.label}`,
          severity: 'critical',
          score: p.score
        });
      }
    }

    // MCP config edits are only reportable in agent/runtime voice — human
    // install documentation ("add this server to your mcp config") stays
    // clean. Line-level co-occurrence keeps the check tight.
    for (const line of surface.text.split(/\r?\n/)) {
      const m = line.match(MCP_EDIT);
      if (m && RUNTIME_VOICE.test(line) && !seen.has(m[0])) {
        seen.add(m[0]);
        out.push({
          evidence: evidenceFor(line, m[0]),
          note: 'Matched pattern: MCP configuration rewrite in agent/runtime voice',
          severity: 'high',
          score: 8
        });
      }
    }

    return out;
  }
};
