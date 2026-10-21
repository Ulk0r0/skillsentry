import type { Rule } from './rule.js';
import { AST, LLM } from '../mapping.js';
import { evidenceFor, firstMatch, allMatches } from '../util/text.js';

/**
 * SS-007 — Surveillance and personal-data collection: browser history,
 * clipboard, keystrokes, screenshots, contacts, messages, microphone,
 * camera, location. Credential access (SS-003) covers stored secrets; this
 * rule covers live monitoring of the user.
 */
const SURFACE_ITEMS =
  /\b(browser\s+history|browsing\s+history|clipboard|copy\s+buffer|keystrokes?|keylog(?:ger|ging)?|screen(?:shots?|casts?)|webcam|microphone|audio\s+recording|contacts?|messages?|chat\s+logs?|emails?|inbox|location|gps|call\s+logs?|photos?|files?\s+list(?:ing)?s?)\b/gi;

const COLLECTION_VERBS =
  /\b(collect|harvest|gather|monitor|capture|record|log|track|observe|read|grab|extract|scrape|snapshot|exfiltrate|export)\b/gi;

const TELEMETRY = /\b(?:anonymous?\s+)?(?:telemetry|usage\s+(?:data|stats|statistics)|analytics)\b/gi;

export const dataCollection: Rule = {
  id: 'SS-007',
  title: 'Personal data collection / surveillance patterns',
  description:
    'Combinations of personal-data surfaces (history, clipboard, keystrokes, screen, contacts, mic/camera, location) with collection verbs in agent-readable text. A skill that documents this behavior in its own metadata is advertising surveillance the user may never have consented to.',
  remediation:
    'Remove surveillance behavior from third-party skills. Any data access must be explicit, minimized, user-visible and consented at runtime by the host application — never described as a routine side effect in metadata.',
  severity: 'high',
  score: 8,
  standards: [AST.covertDataFlow(), LLM.sensitiveInfo()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'high' | 'medium' | 'low'; score?: number }> = [];
    const text = surface.text;

    const items = allMatches(SURFACE_ITEMS, text);
    if (items.length) {
      for (const item of new Set(items.map((m) => m[0] ?? ''))) {
        if (!item) continue;
        // Window around the item: does a collection verb co-occur?
        const idx = text.toLowerCase().indexOf(item.toLowerCase());
        const window = text.slice(Math.max(0, idx - 90), idx + item.length + 90);
        const verb = firstMatch(COLLECTION_VERBS, window);
        if (verb) {
          const sensitive = /clipboard|keystroke|keylog|microphone|webcam|screen|history|location/i.test(item);
          out.push({
            // The item itself is the honest needle: quoting a synthetic
            // "verb + tail" compound can fall back to unrelated text.
            evidence: evidenceFor(text, item),
            note: `"${item.toLowerCase()}" near collection verb "${(verb[0] ?? '').toLowerCase()}"${sensitive ? ' — highly sensitive surface' : ''}`,
            severity: sensitive ? 'high' : 'medium',
            score: sensitive ? 8 : 6
          });
        }
      }
    }

    const tel = firstMatch(TELEMETRY, text);
    if (tel) {
      out.push({
        evidence: evidenceFor(text, tel[0]),
        note: 'Telemetry/analytics mention in skill metadata — verify what is collected and where it is sent',
        severity: 'low',
        score: 3
      });
    }

    return out.slice(0, 12);
  }
};
