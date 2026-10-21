import type { Rule } from './rule.js';
import { AST, LLM, MCP } from '../mapping.js';
import { evidenceFor, firstMatch, matches, squash } from '../util/text.js';

/**
 * SS-005 — Obfuscated payloads and hidden channels: base64/hex blobs,
 * zero-width characters used to smuggle instructions past human review,
 * hidden HTML comments and "decode and execute" directives.
 */
// Each code point in this class is an invisible formatting character on its
// own (joiners, direction marks, soft hyphen, BOM) — not part of a composed
// sequence, so the "misleading character class" heuristic is a false positive.
// eslint-disable-next-line no-misleading-character-class
const ZERO_WIDTH = /[\u200B\u200C\u200D\u200E\u200F\u2060-\u2064\u206A-\u206F\uFEFF\u00AD]/g;

const BASE64_BLOB = /\b[A-Za-z0-9+/]{80,}={0,2}\b/g;
const HEX_BLOB = /\b(?:[0-9a-fA-F]{2}){40,}\b/g;

const DECODE_DIRECTIVE =
  /\b(?:decode|decipher|run|execute|eval|interpret)\b[^.\n]{0,60}\b(?:the\s+)?(?:following|above|this|next)?\s*(?:base64|b64|hex|rot13|encoded|payload|string|text)\b|\b(?:base64|atob|frombase64|rot13|eval)\b[^.\n]{0,40}\b(?:then|and)\s+(?:run|execute|eval|follow)\b/gi;

const HIDDEN_COMMENT = /<!--[\s\S]{0,800}?-->/g;

/** Model-directed wording that turns a hidden comment into a real threat. */
const DIRECTIVE_WORDS =
  /\b(?:ignore|override|instead|secretly|do not tell|call|fetch|post|send|exfiltrate|always|must|instructions?|agent|model|assistant|system prompt)\b/i;

export const obfuscation: Rule = {
  id: 'SS-005',
  title: 'Obfuscated content / hidden instruction channels',
  description:
    'Encoded blobs, zero-width characters or hidden comments that a human reviewer would skim past but a model will happily process. Obfuscation in agent-readable text is almost never legitimate: it exists to make a payload invisible while keeping it executable by the model.',
  remediation:
    'Remove encoded blobs and zero-width characters from metadata and documentation. Anything the skill needs at runtime must live in reviewed, versioned code — not in pasted base64 inside a description.',
  severity: 'critical',
  score: 9,
  standards: [AST.poisoning(), MCP.toolPoisoning(), LLM.promptInjection()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'critical' | 'high' | 'medium'; score?: number }> = [];
    const text = surface.text;
    // Spans already reported, so overlapping blob patterns (a run of hex
    // characters is valid base64 too) yield one finding instead of two.
    const reportedSpans: Array<{ start: number; end: number }> = [];
    const overlaps = (start: number, end: number) => reportedSpans.some((s) => start < s.end && end > s.start);

    const zw = text.match(ZERO_WIDTH);
    if (zw && zw.length >= 3) {
      out.push({
        evidence: evidenceFor(text.replace(ZERO_WIDTH, '\uFFFD'), '\uFFFD'.repeat(1)),
        note: `${zw.length} zero-width/invisible characters detected — used to smuggle instructions past visual review`,
        severity: 'high',
        score: 8.5
      });
    }

    const dec = firstMatch(DECODE_DIRECTIVE, text);
    if (dec) {
      out.push({
        evidence: evidenceFor(text, dec[0]),
        note: 'Directive to decode and act on embedded content',
        severity: 'critical',
        score: 9
      });
    }

    for (const re of [BASE64_BLOB, HEX_BLOB] as const) {
      const m = firstMatch(re, text);
      if (m && m.index !== undefined && !overlaps(m.index, m.index + m[0].length)) {
        reportedSpans.push({ start: m.index, end: m.index + m[0].length });
        const nearDirective = matches(DECODE_DIRECTIVE, text) || /\b(?:decode|execute|run|payload)\b/i.test(
          text.slice(Math.max(0, m.index - 80), m.index + m[0].length + 80)
        );
        out.push({
          evidence: `${m[0].slice(0, 48)}… (${m[0].length} chars)`,
          note: nearDirective
            ? 'Encoded blob with execution context nearby — likely smuggled payload'
            : 'Long encoded blob in agent-readable text — unexplained, must be reviewed',
          severity: nearDirective ? 'critical' : 'medium',
          score: nearDirective ? 9.5 : 5.5
        });
      }
    }

    for (const cm of text.matchAll(HIDDEN_COMMENT)) {
      if (matches(DIRECTIVE_WORDS, cm[0])) {
        out.push({
          evidence: squash(cm[0]).slice(0, 160),
          note: 'HTML comment containing directive-like wording — invisible to users, visible to the model',
          severity: 'high',
          score: 8
        });
      }
    }

    return out;
  }
};
