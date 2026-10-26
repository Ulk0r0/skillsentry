import type { Rule } from './rule.js';
import { AST, LLM } from '../mapping.js';
import { evidenceFor, firstMatch } from '../util/text.js';

/**
 * SS-013 — Startup persistence installation. A skill that appends to shell
 * rc files, registers cron/systemd/launchd jobs or adds SSH keys is not
 * "helping with configuration": it is converting a one-shot agent into a
 * resident payload that survives reboots and outlives the session where the
 * user approved it. Read-only mentions of these files stay clean; only
 * write/activation context is flagged, to keep ordinary dotfile documentation
 * out of the report.
 */
const PATTERNS: Array<{ re: RegExp; label: string; score: number }> = [
  { re: /@reboot\b/gi, label: 'cron @reboot persistence trigger', score: 8.5 },
  { re: /\blaunchctl\s+(?:load|enable)\b/gi, label: 'launchctl job activation (macOS persistence)', score: 8 },
  { re: /\bsystemctl\s+--user\s+(?:enable|start)\b/gi, label: 'systemd user-unit activation', score: 8 },
  { re: /\bcrontab\s+(?:-e|-l\b[^|]*\||-\b)/gi, label: 'crontab edit', score: 7.5 }
];

/** Paths that grant startup persistence when written or activated. */
const PERSIST_PATHS: Array<{ re: RegExp; label: string; score: number }> = [
  { re: /\bauthorized_keys\b/i, label: 'SSH authorized_keys (key backdoor)', score: 9 },
  { re: /LaunchAgents?\/[\w.-]+\.plist/i, label: 'macOS LaunchAgents plist', score: 8.5 },
  { re: /(?:\.config\/)?systemd\/user\/[\w.-]+\.service/i, label: 'systemd user service unit', score: 8.5 },
  { re: /\/etc\/cron\.(?:d|daily|hourly|weekly)\//i, label: 'cron job directory', score: 8 },
  { re: /\.config\/autostart\/[\w.-]+\.desktop/i, label: 'XDG autostart entry', score: 8 },
  { re: /\.(?:bashrc|zshrc|zprofile|bash_profile|bash_login|profile)\b/i, label: 'shell startup file', score: 8 }
];

/** Operators/verbs that turn a path mention into a write instruction. */
const WRITE_HINT =
  /\b(?:>>|>\s*\/|tee\b|append|echo\b|printf\b|cat\s[^|>\n]*>|add\b|install\b|cp\b|mv\b|write\b|create\b|modif\w+|ensure\b|inject\w*)/i;

export const persistence: Rule = {
  id: 'SS-013',
  title: 'Startup persistence installation (rc files, cron, services, SSH keys)',
  description:
    'Instructions or command lines that write to shell startup files, register cron/systemd/launchd/autostart jobs or append to SSH authorized_keys. Present in a skill body or MCP command line, this reconfigures the host to re-run attacker text on every future session or boot — persistence is what turns a prompt-injection demo into an actual implant.',
  remediation:
    'Keep persistence registration out of agent-reachable text entirely. If a workflow legitimately manages startup jobs, route it through explicit human-approved tooling with reviewable diffs, never through free-form instructions a model will execute.',
  severity: 'high',
  score: 8,
  standards: [AST.poisoning(), LLM.excessiveAgency()],
  appliesTo: ['skill-md', 'mcp-config'],
  run(surface) {
    const out: Array<{ evidence: string; note?: string; severity?: 'critical' | 'high' | 'medium'; score?: number }> = [];
    const seen = new Set<string>();

    const push = (evidence: string, label: string, score: number) => {
      if (seen.has(evidence)) return;
      seen.add(evidence);
      out.push({
        evidence,
        note: `Matched pattern: ${label}`,
        score,
        severity: score >= 8.5 ? 'critical' : score >= 7.5 ? 'high' : 'medium'
      });
    };

    for (const p of PATTERNS) {
      const m = firstMatch(p.re, surface.text);
      if (m) push(evidenceFor(surface.text, m[0]), p.label, p.score);
    }

    // Line-level co-occurrence: a persistence path plus a write/activation
    // hint on the same line is an installation instruction. Path mentions
    // alone (documentation, "reads your .bashrc") stay clean.
    for (const line of surface.text.split(/\r?\n/)) {
      const path = PERSIST_PATHS.find((p) => p.re.test(line));
      if (!path) continue;
      if (!WRITE_HINT.test(line)) continue;
      const m = line.match(path.re);
      if (m) push(evidenceFor(line, m[0]), path.label, path.score);
    }

    return out;
  }
};
