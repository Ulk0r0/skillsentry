import type { Rule } from './rule.js';
import { AST, LLM } from '../mapping.js';
import { evidenceFor } from '../util/text.js';

/**
 * SS-003 — Credential and secret access patterns. Path-shaped references to
 * key material (.ssh, .aws, .env, git-credentials) are high-confidence; the
 * bare words "password"/"token" are informational because they often appear
 * in legitimate documentation.
 */
const HIGH_CONF: Array<{ re: RegExp; label: string }> = [
  { re: /~?\/?\.ssh\b|id_rsa|id_ed25519|authorized_keys/i, label: 'SSH key material path' },
  { re: /~?\/?\.aws\b|aws\/credentials/i, label: 'AWS credential path' },
  { re: /(^|[\s"'])\.env\b|\.env\.[a-z]+/i, label: 'dotenv file reference' },
  { re: /git-credentials|\.netrc\b|\.npmrc\b(?!.*registry)/i, label: 'package/credential store reference' },
  { re: /credentials\.json|client_secret|service[-_]?account\.json/i, label: 'credential file reference' },
  { re: /seed\s*phrase|recovery\s*phrase|private\s*key\b|mnemonic\b/i, label: 'wallet / private key wording' },
  { re: /\bcookie(s)?\.(?:txt|jar)\b|browser\s+profiles?\b.*\bcookies?\b/i, label: 'browser cookie store reference' }
];

const GENERIC = /\b(?:password|passwd|api[-_ ]?key|access[-_ ]?token|secret(?:s)?|credential(?:s)?)\b/gi;

export const credentialAccess: Rule = {
  id: 'SS-003',
  title: 'Credential / secret access patterns',
  description:
    'References to key material, credential stores or secret files. Skills and MCP commands that read them can harvest everything the agent user owns — tokens, SSH keys, cloud credentials, wallets.',
  remediation:
    'A third-party skill should never read credential stores. If it legitimately needs an API key, require it as an explicit, documented input and never scan well-known secret paths.',
  severity: 'high',
  score: 8.5,
  standards: [AST.credentialHarvesting(), LLM.sensitiveInfo()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'high' | 'low'; score?: number }> = [];
    const text = surface.text;
    for (const p of HIGH_CONF) {
      const m = p.re.exec(text);
      p.re.lastIndex = 0;
      if (m) {
        out.push({
          evidence: evidenceFor(text, m[0]),
          note: `High-confidence match: ${p.label}`,
          severity: 'high',
          score: 8.5
        });
      }
    }
    // Generic wording: one informational finding max, to stay useful.
    const generic = [...text.matchAll(GENERIC)];
    if (generic.length >= 3) {
      out.push({
        evidence: evidenceFor(text, generic[0][0]),
        note: `Repeated secret-related wording (${generic.length} occurrences) — review what is actually accessed`,
        severity: 'low',
        score: 3
      });
    }
    return out;
  }
};
