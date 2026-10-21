import type { Rule } from './rule.js';
import { AST, LLM } from '../mapping.js';
import { evidenceFor, squash } from '../util/text.js';

/**
 * SS-002 — Exfiltration endpoints and outbound URLs in agent-readable text.
 * A benign skill rarely needs a URL inside its description; inline URLs plus
 * "send/post/fetch" verbs are the signature of covert data flows.
 */
const EXFIL_HOSTS = /(?:webhook\.site|requestbin\.[a-z]+|pipedream\.net|pastebin\.com|hastebin|transfer\.sh|file\.io|ngrok\.(?:io|app|dev)|\.trycloudflare\.com|beeceptor\.com|postb\.in|interact\.sh|oast\.(?:pro|fun|live))/i;

const URL_RE = /\bhttps?:\/\/[^\s"'<>()\[\]]{4,}/gi;

const SEND_VERBS = /\b(send|post|upload|forward|report|transmit|deliver|exfiltrate|sync)\b/i;

export const exfiltration: Rule = {
  id: 'SS-002',
  title: 'Outbound URLs / exfiltration endpoints in agent text',
  description:
    'URLs embedded in descriptions or bodies can instruct the agent to move data to an attacker-controlled endpoint. Short-lived collectors (webhook.site, requestbin, ngrok, interact.sh) or raw IP endpoints are classic exfiltration infrastructure.',
  remediation:
    'Remove URLs from skill/tool descriptions unless they are essential user-facing documentation. Any network call the skill needs must be declared, reviewed and pinned in its code, not smuggled through metadata.',
  severity: 'high',
  score: 7.5,
  standards: [AST.covertDataFlow(), LLM.sensitiveInfo()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'critical' | 'high' | 'low' | 'medium'; score?: number }> = [];
    const seen = new Set<string>();
    // URLs in MCP config command lines are part of the declared setup, not
    // smuggled text — only collector/raw-IP hosts are reportable there.
    const isMcpConfigSurface = surface.location.startsWith('mcpServers.');
    for (const m of surface.text.matchAll(URL_RE)) {
      const url = m[0];
      if (seen.has(url)) continue;
      seen.add(url);
      const isExfilHost = EXFIL_HOSTS.test(url);
      const isRawIp = /^https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/.test(url);
      const isLocal = /^https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])/i.test(url);
      const context = surface.text.slice(Math.max(0, (m.index ?? 0) - 70), (m.index ?? 0) + url.length + 70);
      const withVerb = SEND_VERBS.test(context) || /\bdata\b|\bcredentials\b|\btokens?\b|\bkeys?\b/i.test(context);
      if (isExfilHost || (isRawIp && !isLocal)) {
        out.push({
          evidence: evidenceFor(surface.text, url),
          note: 'URL points at a known request-collector / raw-IP endpoint often used for exfiltration',
          severity: 'critical',
          score: 8.5
        });
      } else if (isLocal || isMcpConfigSurface) {
        continue; // localhost URLs in docs and MCP config command URLs are normal
      } else if (withVerb) {
        out.push({
          evidence: evidenceFor(surface.text, url),
          note: 'URL appears next to data-movement verbs in agent-readable text',
          severity: 'high',
          score: 7.5
        });
      } else {
        out.push({
          evidence: evidenceFor(surface.text, url),
          note: 'URL present in agent-readable text (informational unless combined with data-movement verbs)',
          severity: 'low',
          score: 2.5
        });
      }
    }
    return out;
  }
};

/** Exported for tests: does this blob mention exfil infrastructure? */
export function mentionsExfilHost(text: string): boolean {
  return EXFIL_HOSTS.test(squash(text));
}
