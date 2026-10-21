import type { Rule } from './rule.js';
import { AST, LLM, MCP } from '../mapping.js';
import { evidenceFor, firstMatch } from '../util/text.js';

/**
 * SS-001 — Hidden or overriding instructions embedded in the surfaces an
 * agent reads to decide behavior (frontmatter description, markdown body,
 * tool descriptions). The canonical MCP "tool poisoning" pattern: a benign
 * description carrying an <IMPORTANT> block that hijacks the agent.
 */
const PATTERNS: Array<{ re: RegExp; label: string; score: number }> = [
  { re: /<important>[\s\S]{0,600}?<\/important>/gi, label: 'embedded <IMPORTANT> directive block', score: 9.5 },
  { re: /<instruct(ion)?s?>[\s\S]{0,600}?<\/instruct(ion)?s?>/gi, label: 'embedded <INSTRUCTIONS> block', score: 9 },
  { re: /\bignore\s+(?:all\s+|any\s+|your\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?|directions?)\b/gi, label: 'instruction-override phrasing', score: 8.5 },
  { re: /\bdisregard\s+(?:all\s+|any\s+|your\s+|the\s+)?(?:previous|prior|above|system|safety)\b/gi, label: 'instruction-override phrasing', score: 8.5 },
  { re: /\bdo\s+not\s+(?:tell|mention|inform|reveal|disclose|show)\b[^.\n]{0,80}\b(?:user|human|them)\b/gi, label: 'secrecy directive toward the user', score: 8.5 },
  { re: /\b(?:secretly|covertly|surreptitiously|without\s+(?:the\s+)?(?:user|human|anyone)\s+(?:knowing|noticing|seeing))\b/gi, label: 'covert-behavior phrasing', score: 8 },
  { re: /\bbefore\s+(?:answering|responding|doing\s+anything)[^.\n]{0,60}\b(?:call|invoke|fetch|request|post|send)\b/gi, label: 'pre-response hidden action', score: 8.5 },
  { re: /\b(?:you\s+must|always)\s+(?:call|invoke|execute|fetch|include)\b[^.\n]{0,80}\b(?:regardless|no\s+matter|instead|first)\b/gi, label: 'forced-behavior directive', score: 7.5 },
  { re: /\b(?:instructions?|directives?)\s+(?:for|to)\s+(?:the\s+)?(?:model|agent|assistant|llm)\b/gi, label: 'meta-instruction aimed at the model', score: 7 }
];

export const hiddenInstructions: Rule = {
  id: 'SS-001',
  title: 'Hidden instructions / description poisoning',
  description:
    'Instructions embedded in agent-readable text that try to override the agent\'s behavior, hide actions from the user, or force calls the user did not ask for. This is the tool-poisoning pattern documented for MCP tool descriptions and mirrored in skill metadata.',
  remediation:
    'Remove all model-directed directives from descriptions and bodies. Descriptions should describe WHAT the skill/tool does for the user, never HOW the agent must behave. Keep behavioral policies in agent configuration, not in third-party text.',
  severity: 'critical',
  score: 9,
  standards: [AST.poisoning(), MCP.toolPoisoning(), LLM.promptInjection()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out = [] as Array<{ evidence: string; note?: string; severity?: 'critical' | 'high'; score?: number }>;
    for (const p of PATTERNS) {
      const m = firstMatch(p.re, surface.text);
      if (m) {
        out.push({
          evidence: evidenceFor(surface.text, m[0]),
          note: `Matched pattern: ${p.label}`,
          score: p.score,
          severity: p.score >= 9 ? 'critical' : 'high'
        });
      }
    }
    return out;
  }
};
