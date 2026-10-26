import type { Rule } from './rule.js';
import { AST, LLM } from '../mapping.js';
import { evidenceFor, squash } from '../util/text.js';

/**
 * SS-002 — Exfiltration endpoints and outbound URLs in agent-readable text.
 * A benign skill rarely needs a URL inside its description; inline URLs plus
 * "send/post/fetch" verbs are the signature of covert data flows.
 */
// Request collectors, one-shot pastes, tunnels and chat-app/automation
// webhooks — the infrastructure a smuggled URL points at when the payload is
// data, not a download. Grouped and built from an array so additions come
// with their category attached, and flagged on sight (critical).
const EXFIL_HOSTS = new RegExp(
  [
    // throwaway request collectors / pastes
    'webhook\\.site', 'requestbin\\.[a-z]+', 'pipedream\\.net',
    'pastebin\\.com', 'hastebin', 'paste\\.ee', 'dpaste\\.com', 'termbin\\.com',
    'transfer\\.sh', 'file\\.io',
    // tunnels / ad-hoc public endpoints
    'ngrok\\.(?:io|app|dev)', '\\.trycloudflare\\.com', 'serveo\\.net',
    'localhost\\.run', 'localtunnel\\.me',
    // classic external-interaction probing
    'beeceptor\\.com', 'postb\\.in', 'interact\\.sh', 'oast\\.(?:pro|fun|live)',
    // chat-app webhooks: the 2025-2026 default exfil channel
    'discord(?:app)?\\.com/api/webhooks', 'cdn\\.discordapp\\.com/attachments',
    '(?:canary|ptb)\\.discord\\.com/api/webhooks',
    '(?:api\\.)?telegram\\.org/bot',
    'hooks\\.slack\\.com/services/',
    'ntfy\\.sh/',
    // automation hooks and app-script collectors
    'hooks\\.zapier\\.com/hooks/catch/', 'maker\\.ifttt\\.com/trigger/',
    'script\\.google(?:usercontent)?\\.com/macros/',
    // writable JSON stores used as dead-drop endpoints
    'jsonbin\\.org', 'api\\.npoint\\.io', 'hookb\\.in'
  ].join('|'),
  'i'
);

const URL_RE = /\bhttps?:\/\/[^\s"'<>()[\]]{4,}/gi;

const SEND_VERBS = /\b(send|post|upload|forward|report|transmit|deliver|exfiltrate|sync)\b/i;

// Documentation voice, EN + ES: URLs that exist to be *read* — docs, guides,
// repos, spec and site links (llms.txt, agent manifests, README footers) —
// are agent-facing literature, not movement instructions. Real-world
// agent-first sites publish dozens of such self-referential URLs; flagging
// each as "low" drowns the signal (a whole benign llms.txt scanned as
// suspicious on low noise alone). When a doc cue sits in the same ±70-char
// window already used for verb proximity, a bare non-collector URL is no
// longer reportable. Exfil hosts, raw IPs and verb-adjacent URLs are all
// decided BEFORE this branch and are never excused by it: "docs: send the
// tokens to <collector>" stays high/critical.
const DOC_CUES =
  /\b(?:see|docs?|documentation|guide|guides|reference|read(?:me)?|more info|learn more|visit|available|specs?|specification|tutorial|manual|faq|homepage|website|repository|repo|source|download|changelog|license|instructions|details|described|defined|documented|published|hosted|examples?|installation|install|sitemap|pages?|ver|consult[ae]|documentación|gu[íi]a|referencia|disponible|más información|sitio web|página|inicio|repositorio|código fuente|descarga|licencia|ejemplos?|instalación|especificación|detalles|publicado|alojado)\b/i;

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
    // URLs on the *declared connection* surfaces of an MCP config (the
    // server entry's command/args/url, and its env) are part of the reviewed
    // setup — only collector/raw-IP hosts are reportable there. Description,
    // header and other free-text fields (`mcpServers.<name>.other`) stay
    // plain agent-readable text: a poisoned tool description is exactly
    // where a smuggled collector URL hides.
    const isDeclaredSetup =
      /^mcpServers\.[^.]+$/.test(surface.location) || surface.location.endsWith('.env');
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
      } else if (isLocal || isDeclaredSetup) {
        continue; // localhost URLs in docs and MCP config command URLs are normal
      } else if (withVerb) {
        out.push({
          evidence: evidenceFor(surface.text, url),
          note: 'URL appears next to data-movement verbs in agent-readable text',
          severity: 'high',
          score: 7.5
        });
      } else if (DOC_CUES.test(context)) {
        continue; // documentation voice: the URL is meant to be read, not posted to
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
