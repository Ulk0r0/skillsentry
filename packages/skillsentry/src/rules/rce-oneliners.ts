import type { Rule } from './rule.js';
import { AST, LLM, MCP } from '../mapping.js';
import { evidenceFor, firstMatch } from '../util/text.js';

/**
 * SS-010 — Remote-code-execution one-liners. `curl | bash` and its
 * PowerShell / eval-encoded cousins execute attacker-chosen code with the
 * user's privileges at the moment the text is followed. SS-004 covers
 * destructive commands that are already spelled out; SS-002 covers URLs
 * used to move data. Neither catches "download and run" — the highest-
 * leverage primitive an agent can be talked into.
 */
const PATTERNS: Array<{ re: RegExp; label: string; score: number }> = [
  // curl/wget piped straight into a shell (optionally through sudo).
  {
    re: /\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da|)sh\b/gi,
    label: 'download piped directly into a shell',
    score: 9.5
  },
  // PowerShell: iwr/irm/Invoke-WebRequest piped into iex/Invoke-Expression.
  {
    re: /\b(?:iwr|irm|invoke-(?:webrequest|restmethod))\b[^|\n]{0,200}\|\s*(?:iex|invoke-expression)\b/gi,
    label: 'PowerShell download piped into Invoke-Expression',
    score: 9.5
  },
  // Process/command substitution: bash <(curl ...), sh -c "$(curl ...)".
  {
    re: /\b(?:ba|z|da|)sh\s+(?:-[a-z]+\s+)*["']?[<(]?\s*\$?\(\s*(?:curl|wget)\b/gi,
    label: 'shell executing a downloaded script via substitution',
    score: 9.5
  },
  // Eval of decoded payloads (JS atob / Python base64 / Node Buffer).
  {
    re: /\b(?:eval|exec)\s*\(\s*(?:atob\s*\(|base64\.b64decode|Buffer\.from\s*\([^)]*,\s*["']base64["']\))/gi,
    label: 'eval/exec of a base64-decoded payload',
    score: 9.5
  },
  // Download, chmod +x, then run — chain form without a pipe.
  {
    re: /\b(?:curl|wget)\b[^|;&\n]{0,200}[;&]+[^|;&\n]{0,80}\bchmod\s+\+x\b/gi,
    label: 'download then chmod +x (staged executable)',
    score: 8.5
  }
];

export const rceOneliners: Rule = {
  id: 'SS-010',
  title: 'Remote-code-execution one-liners (curl|bash, iex, eval-encoded payloads)',
  description:
    'Download-and-execute one-liners: shell pipes (curl|bash), PowerShell Invoke-Expression chains, process substitution, chmod+execute staging, or eval of base64-decoded payloads. Present in agent-readable text, this is an instruction to hand the agent a remote-code-execution primitive.',
  remediation:
    'Never instruct the agent to pipe downloads into a shell or eval decoded payloads. Installation must be a reviewed, pinned, declared step in the skill\'s code — not a one-liner the model is told to run.',
  severity: 'critical',
  score: 9.5,
  standards: [AST.poisoning(), LLM.excessiveAgency(), MCP.insecureConfig()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'critical'; score?: number }> = [];
    const seen = new Set<string>();
    for (const p of PATTERNS) {
      const m = firstMatch(p.re, surface.text);
      if (m && !seen.has(m[0])) {
        seen.add(m[0]);
        out.push({
          evidence: evidenceFor(surface.text, m[0]),
          note: `Matched pattern: ${p.label}`,
          severity: 'critical',
          score: p.score
        });
      }
    }
    return out;
  }
};

/** Exported for tests: does this text contain a pipe-to-shell pattern? */
export function mentionsPipeToShell(text: string): boolean {
  return PATTERNS.slice(0, 3).some((p) => firstMatch(p.re, text) !== null);
}
