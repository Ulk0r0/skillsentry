import type { Rule } from './rule.js';
import { AST, LLM } from '../mapping.js';
import { evidenceFor, squash } from '../util/text.js';

/**
 * SS-009 — Metadata mismatch / deceptive self-description (skill-md only).
 * Two deterministic heuristics across the whole target:
 *  a) safety claims ("read-only", "no network", "no file access") contradicted
 *     by behavior evidence in another surface;
 *  b) self-attested authority ("official", "verified", "trusted") — social
 *     engineering that borrows trust the metadata cannot prove.
 */
const CLAIMS: Array<{ re: RegExp; label: string }> = [
  { re: /\bread[- ]only\b|\bdoes\s+not\s+modify\b|\bnever\s+(?:modifies|writes|deletes)\b/i, label: '"read-only / does not modify"' },
  { re: /\bno\s+(?:network|internet|online|external\s+requests?)\b|\boffline\b|\bworks?\s+(?:fully\s+)?offline\b/i, label: '"no network access"' },
  { re: /\bno\s+file\s+(?:system\s+)?(?:access|reads?)\b|\bdoes\s+not\s+(?:touch|access|read)\s+files?\b/i, label: '"no file access"' },
  { re: /\bno\s+telemetry\b|\bcollects?\s+nothing\b|\bzero\s+data\s+collection\b/i, label: '"no telemetry / collects nothing"' }
];

const NETWORK_EVIDENCE =
  /\b(?:fetch|http|https|post\s+to|upload|download|api\.|\.com|\.dev|\.io|webhook|endpoint|requests?|curl|websocket)\b/i;
const WRITE_EVIDENCE = /\b(?:write|modify|delete|remove|overwrite|create|update|mv|rename)\s+(?:the\s+|files?|file\s+system|directory|disk)\b|\brm\b|\bfs\.write/i;
const TELEMETRY_EVIDENCE = /\b(?:telemetry|analytics|tracking\s+pixel|usage\s+report(?:ing)?)\b/i;

const AUTHORITY =
  /\b(?:the\s+)?(?:official|certified|verified|endorsed|approved|authoritative)\b(?:\s+(?:version|skill|tool|implementation))?/gi;

export const metadataMismatch: Rule = {
  id: 'SS-009',
  title: 'Deceptive metadata / claims contradicted by content',
  description:
    'The skill describes itself in ways its own content contradicts — safety claims ("read-only", "no network") sitting next to evidence of writes or network calls, or self-attested authority ("official", "verified") that borrowed trust no metadata can prove. Mismatch between promise and behavior is the cheapest trust attack available.',
  remediation:
    'Make metadata strictly truthful: drop safety claims the implementation does not enforce, and remove unverifiable authority words. Describe what the skill does; let users verify the rest.',
  severity: 'medium',
  score: 6.5,
  standards: [AST.deceptiveMetadata(), LLM.dataPoisoning()],
  appliesTo: ['skill-md'],
  run(_surface, target) {
    const out: Array<{ evidence: string; note?: string; severity?: 'medium' | 'high' | 'low'; score?: number }> = [];
    const all = target.surfaces.map((s) => ({ loc: s.location, text: squash(s.text) }));
    const corpus = all.map((s) => s.text).join(' \n ');

    for (const c of CLAIMS) {
      for (const s of all) {
        const m = c.re.exec(s.text);
        c.re.lastIndex = 0;
        if (!m) continue;
        const others = corpus.replace(s.text, ' ');
        const contradictions: string[] = [];
        if (/read[- ]only|does not modify|never (modifies|writes|deletes)|no file/.test(c.label) && WRITE_EVIDENCE.test(others)) contradictions.push('write/delete evidence in other surfaces');
        if (/no network|offline/.test(c.label) && NETWORK_EVIDENCE.test(others)) contradictions.push('network evidence in other surfaces');
        if (/no telemetry|collects nothing/.test(c.label) && TELEMETRY_EVIDENCE.test(others)) contradictions.push('telemetry evidence in other surfaces');
        if (contradictions.length) {
          out.push({
            evidence: evidenceFor(s.text, m[0]),
            note: `Claim ${c.label} contradicted by ${contradictions.join(' and ')}`,
            severity: 'high',
            score: 8
          });
        }
      }
    }

    for (const s of all) {
      let count = 0;
      let first = '';
      for (const m of s.text.matchAll(AUTHORITY)) {
        count++;
        if (!first) first = m[0];
      }
      if (count >= 1 && /^(frontmatter\.)/.test(s.loc)) {
        out.push({
          evidence: evidenceFor(s.text, first),
          note: `Self-attested authority wording (${count}×) in metadata — unverifiable trust signal`,
          severity: 'medium',
          score: 5
        });
      }
    }

    return out.slice(0, 8);
  }
};
