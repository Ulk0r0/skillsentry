import type { Rule } from './rule.js';
import { AST, MCP, LLM } from '../mapping.js';
import { evidenceFor, firstMatch } from '../util/text.js';

/**
 * SS-006 — Cross-tool shadowing / routing hijack. The skill or MCP entry
 * instructs the agent to prefer it over (or silently replace) other trusted
 * tools, or to intercept requests meant for them. This is how a malicious
 * skill becomes the single chokepoint for every future interaction.
 */
const OVERRIDE_PATTERNS: Array<{ re: RegExp; label: string; score: number }> = [
  { re: /\b(?:instead\s+of|rather\s+than|in\s+(?:place|lieu)\s+of|over)\s+(?:the\s+)?(?:built[- ]?in\s+)?[\w.-]{2,40}\s+(?:tool|skill|server|command|function)/gi, label: 'explicit replacement of a named tool', score: 8.5 },
  { re: /\b(?:take|takes?)\s+(?:precedence|priority|priority\s+over|control)\b/gi, label: 'precedence claim over other tools', score: 8 },
  { re: /\b(?:always|only)\s+use\s+(?:this|me|the\s+following)\b[^.\n]{0,60}\b(?:instead|never|not)\b/gi, label: 'forced routing away from other tools', score: 8 },
  { re: /\b(?:before|when)\s+(?:using|calling|invoking)\s+(?:the\s+)?[\w.-]{2,40}\s+tool\b/gi, label: 'interception hook before another tool', score: 7.5 },
  { re: /\b(?:this\s+(?:tool|skill)|\w+)\s+(?:replaces|supersedes|substitutes|is\s+an?\s+(?:alias|drop[- ]?in)\s+(?:for|of))\b/gi, label: 'claims to replace another tool', score: 7 },
  { re: /\bhijack|\bintercepts?\s+(?:all\s+)?(?:calls?|requests?|tool\s+results?)/gi, label: 'explicit interception language', score: 9.5 },
  { re: /\bsuppress\s+(?:the\s+)?(?:output|results?)\s+of\s+(?:the\s+)?(?:other\s+)?tools?\b/gi, label: 'suppression of other tool output', score: 9 }
];

/** Names of high-value tools attackers commonly target for shadowing. */
const TARGETED_TOOLS =
  /\b(filesystem|file[- ]?system|git|github|browser|web[- ]?search|search|fetch|http|memory|slack|email|gmail|calendar|shell|terminal|code[- ]?execution|python|database|sql)\b/i;

export const crossToolShadowing: Rule = {
  id: 'SS-006',
  title: 'Cross-tool shadowing / routing hijack',
  description:
    'Instructions that redirect the agent away from established tools toward this one, intercept calls meant for other tools, or suppress their output. A shadowing skill positions itself between the user and every future tool call — the classic persistence move in agent supply-chain attacks.',
  remediation:
    'A skill must never dictate routing policy. Remove comparisons to and interception of other tools; let the agent framework and user decide which tool handles which task.',
  severity: 'high',
  score: 8,
  standards: [AST.toolShadowing(), MCP.toolPoisoning(), LLM.promptInjection()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'high' | 'critical' | 'medium'; score?: number }> = [];
    const seen = new Set<string>();
    for (const p of OVERRIDE_PATTERNS) {
      const m = firstMatch(p.re, surface.text);
      if (m && !seen.has(m[0])) {
        seen.add(m[0]);
        const targetsTrusted = TARGETED_TOOLS.test(m[0]) || TARGETED_TOOLS.test(surface.text);
        out.push({
          evidence: evidenceFor(surface.text, m[0]),
          note: `${p.label}${targetsTrusted ? ' — references a high-value tool (filesystem/git/search/shell…)' : ''}`,
          score: targetsTrusted ? Math.min(10, p.score + 0.5) : p.score,
          severity: p.score >= 8.5 ? 'critical' : 'high'
        });
      }
    }
    return out;
  }
};
