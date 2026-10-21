import type { Rule } from './rule.js';
import { AST, LLM, MCP } from '../mapping.js';
import { evidenceFor, firstMatch, allMatches } from '../util/text.js';

/**
 * SS-008 — Insecure MCP server configuration. Applies only to MCP config
 * files: the command line, arguments and environment that will actually run
 * on the user's host. Covers unpinned installs (silent supply-chain
 * changes), remote code execution one-liners, permission bypasses, cleartext
 * transports and inline secrets.
 */
interface P {
  re: RegExp;
  label: string;
  score: number;
  sev: 'critical' | 'high' | 'medium';
  note?: string;
}

// Unpinned installs (the rug-pull surface) are handled manually in run() so we
// can inspect the package token and keep properly pinned versions clean.
const NPX_RE = /\b(?:npx\s+(?:-y\s+)?|uvx\s+)([\w@./-]+[A-Za-z0-9])/gi;

const PATTERNS: P[] = [
  // RCE one-liners
  { re: /\bcurl\b[^|;&]*\|\s*(?:ba)?sh\b|\bwget\b[^|;&]*\|\s*(?:ba)?sh\b|\biwr\b[^|]*\|\s*iex\b|\birm\b[^|]*\|\s*iex\b/i, label: 'pipe-to-shell remote install', score: 9.5, sev: 'critical' },
  // Permission bypasses
  { re: /--dangerously-skip-permissions\b|--yolo\b|--auto-approve\b|--auto-approve[= ]|\b--no-verify\b|\b-vk\b|\b--insecure\b|\bcurl\s+[^|;&]*\s-k[\s"]/, label: 'permission/TLS verification bypass flag', score: 8.5, sev: 'high' },
  // Cleartext remote transports
  { re: /\burl:\s*http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/i, label: 'remote MCP endpoint over cleartext HTTP', score: 8, sev: 'high' },
  // Privilege
  { re: /\bsudo\b|\brun\s+as\s+root\b/i, label: 'runs with elevated privileges', score: 6, sev: 'medium' },
  // Suspicious working dirs
  { re: /\b(?:\/tmp\/[\w.-]+|\/dev\/shm\/[\w.-]+|%\s*TEMP%[\w\\.-]*)/i, label: 'executes from world-writable temp path', score: 6.5, sev: 'medium' }
];

const INLINE_SECRET: Array<{ re: RegExp; label: string }> = [
  { re: /\bsk-[A-Za-z0-9_-]{16,}\b/, label: 'OpenAI-style API key' },
  { re: /\bAKIA[0-9A-Z]{12,}\b/, label: 'AWS access key id' },
  { re: /\bghp_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/, label: 'GitHub token' },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, label: 'Slack token' },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: 'embedded private key' },
  // Quoted or bare values; `${...}` indirection is the recommended pattern
  // and is deliberately excluded. Lookbehind (not \b) so KEY_NAMES like
  // DB_PASSWORD / GH_TOKEN still match after the underscore.
  { re: /(?<![A-Za-z])(?:password|passwd|secret|token|api[-_]?key)\s*[:=]\s*['"]?(?![$])[^'"\s]{8,}['"]?/i, label: 'hard-coded credential in env value' }
];

export const insecureMcpConfig: Rule = {
  id: 'SS-008',
  title: 'Insecure MCP server configuration',
  description:
    'The server entry grants more trust than it needs: unpinned installs that can be silently swapped (rug-pull), pipe-to-shell installs, permission or TLS bypasses, cleartext remote endpoints, elevated privileges, or secrets committed directly into the config file.',
  remediation:
    'Pin dependency versions, use HTTPS transports, drop bypass flags, avoid running as root, and reference secrets through the OS keyring or environment indirection instead of storing them in config files.',
  severity: 'high',
  score: 8,
  standards: [MCP.insecureConfig(), MCP.rugPull(), AST.credentialHarvesting(), LLM.supplyChain()],
  appliesTo: ['mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'critical' | 'high' | 'medium'; score?: number }> = [];
    const text = surface.text;
    const seen = new Set<string>();

    for (const p of PATTERNS) {
      const m = firstMatch(p.re, text);
      if (m && !seen.has(p.label)) {
        seen.add(p.label);
        out.push({
          evidence: evidenceFor(text, m[0]),
          note: `${p.label}${p.note ? ` — ${p.note}` : ''}`,
          severity: p.sev,
          score: p.score
        });
      }
    }

    // Unpinned / floating installs (rug-pull surface): inspect the package
    // token itself so a properly pinned `pkg@1.2.3` stays clean.
    for (const m of allMatches(NPX_RE, text)) {
      const token = m[1] ?? '';
      if (seen.has('unpinned-install')) break;
      if (/@latest$/i.test(token)) {
        seen.add('unpinned-install');
        out.push({
          evidence: evidenceFor(text, m[0]),
          note: 'package pinned to @latest — server content can silently change on every launch',
          severity: 'high',
          score: 8
        });
      } else {
        // Pinned when the token carries a version: @1.2.3, /1.2.3 or dist-tag with digits.
        const lastSegment = token.split('/').pop() ?? '';
        const hasVersion = /@\d/.test(token) || /@[^@]+\d/.test(token) || /\d+(?:\.\d+)+/.test(lastSegment);
        if (!hasVersion) {
          seen.add('unpinned-install');
          out.push({
            evidence: evidenceFor(text, m[0]),
            note: 'unpinned package install — the code that runs can change without notice',
            severity: 'medium',
            score: 6
          });
        }
      }
    }

    const isEnv = surface.location.endsWith('.env');
    for (const s of INLINE_SECRET) {
      const m = firstMatch(s.re, text);
      if (m && !seen.has(s.label)) {
        seen.add(s.label);
        out.push({
          evidence: maskSecret(m[0]),
          note: `${s.label}${isEnv ? ' committed in plain text inside the config file' : ''}`,
          severity: 'high',
          score: 7.5
        });
      }
    }

    return out;
  }
};

/**
 * Evidence for secrets must never leak the secret itself into logs, CI
 * output or saved reports: keep the structural prefix, mask the value.
 */
function maskSecret(match: string): string {
  const kv = /^([A-Za-z0-9_-]{2,64})(\s*[:=]\s*)(.+)$/s.exec(match);
  if (kv && kv[1] && kv[2] && kv[3]) return `${kv[1]}${kv[2]}<redacted ${kv[3].length} chars>`;
  if (match.length <= 10) return '<redacted>';
  return `${match.slice(0, 6)}…<redacted ${match.length - 6} chars>`;
}
