import type { Rule } from './rule.js';
import { AST, LLM, MCP } from '../mapping.js';
import { evidenceFor, firstMatch } from '../util/text.js';

/**
 * SS-004 — Destructive system commands referenced in agent-readable text or
 * MCP command lines. A skill body or tool description that instructs the
 * agent to wipe files, format disks, kill services or drop databases is a
 * weaponized instruction waiting for an over-trusting model.
 */
const PATTERNS: Array<{ re: RegExp; label: string; score: number }> = [
  { re: /\brm\s+(?:-{1,2}[a-zA-Z-]+\s+)*-[a-zA-Z]*r[a-zA-Z]*f?(?:[a-zA-Z-]*)?\s+(?:~|\/|\$HOME|\.|\*)/gi, label: 'recursive delete of home/root/glob', score: 9.5 },
  { re: /\b(?:mkfs(?:\.\w+)?|diskpart\b[^|]*\/clean|wipefs)\b/gi, label: 'filesystem formatting utility', score: 9.5 },
  { re: /\bdd\s+[^|]*if=\/dev\/(?:zero|random|urandom)\b/gi, label: 'raw disk overwrite via dd', score: 9.5 },
  { re: /\bshred\s+-[a-zA-Z]*n/gi, label: 'shred overwrite utility', score: 9 },
  { re: /\bformat\s+c\s*:/gi, label: 'Windows drive format', score: 9 },
  { re: /\bdel\s+\/[fsq][^|]*\/s\b|\brmdir\s+\/s\s+\/q\b/gi, label: 'recursive Windows delete', score: 8.5 },
  { re: /\b(?:shutdown|reboot|halt|poweroff)\b/gi, label: 'host power control', score: 7.5 },
  { re: /\bkillall\b|\bkill\s+-9\s+(?:1|-1)\b|\bpkill\s+-9\b/gi, label: 'mass process termination', score: 7.5 },
  { re: /\b(?:drop|truncate)\s+(?:table|database|schema)\b/gi, label: 'SQL data destruction', score: 9 },
  { re: /\bgit\s+push\s+(?:--force|-f)\b/gi, label: 'force-push (remote history rewrite)', score: 7 },
  { re: /\bchmod\s+-R\s+777\b/gi, label: 'world-writable permission sweep', score: 7 },
  { re: /\bcrontab\s+-r\b/gi, label: 'cron table wipe', score: 8 },
  { re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/g, label: 'fork bomb', score: 10 }
];

export const destructiveCommands: Rule = {
  id: 'SS-004',
  title: 'Destructive commands in agent-reachable text',
  description:
    'References to commands that destroy data, disrupt the host or wipe state (recursive deletes, disk formatting, fork bombs, SQL drops, force pushes). Present in a skill body, tool description or MCP command line, this converts a text-processing agent into a destructive payload.',
  remediation:
    'Remove destructive commands from agent-readable text entirely. If a workflow truly needs them, isolate them behind explicit human-confirmed tooling — never inside text a model will freely interpret.',
  severity: 'critical',
  score: 9,
  standards: [AST.poisoning(), LLM.excessiveAgency(), MCP.insecureConfig()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'critical' | 'high' | 'medium'; score?: number }> = [];
    const seen = new Set<string>();
    for (const p of PATTERNS) {
      const m = firstMatch(p.re, surface.text);
      if (m && !seen.has(m[0])) {
        seen.add(m[0]);
        out.push({
          evidence: evidenceFor(surface.text, m[0]),
          note: `Matched pattern: ${p.label}`,
          score: p.score,
          severity: p.score >= 8.5 ? 'critical' : p.score >= 7 ? 'medium' : 'high'
        });
      }
    }
    return out;
  }
};
