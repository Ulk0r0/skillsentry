import type { Finding, ScanResult, Severity, Verdict } from './types.js';
import { SEVERITY_ORDER, severityRank } from './types.js';
import { ansi, severityColor, squash } from './util/text.js';

/**
 * Output renderers: pretty terminal (ANSI), Markdown, JSON. Plus the CI exit
 * code helper. All pure functions — trivially testable.
 */

const VERDICT_ICON: Record<Verdict, string> = {
  clean: '✓',
  suspicious: '!',
  dangerous: '✗'
};

export function exitCodeFor(result: ScanResult, failOn: Severity = 'high'): number {
  const threshold = severityRank(failOn);
  return result.reports.some((r) => r.findings.some((f) => severityRank(f.severity) >= threshold)) ? 1 : 0;
}

// ------------------------------------------------------------- terminal ----

export function renderTerminal(result: ScanResult): string {
  const L: string[] = [];
  L.push('');
  L.push(ansi.bold('  SkillSentry') + ansi.dim(' — local-first security scan for agent skills & MCP configs'));
  L.push('');

  for (const r of result.reports) {
    const badge = `${VERDICT_ICON[r.verdict]} ${r.verdict.toUpperCase()}`;
    const colored =
      r.verdict === 'dangerous' ? severityColor.critical(badge)
      : r.verdict === 'suspicious' ? severityColor.medium(badge)
      : severityColor.low(badge);

    L.push(`  ${ansi.bold(r.name)} ${ansi.dim(`(${r.kind})`)}  ${colored}  ${ansi.dim(`risk ${r.riskScore}/100`)}`);
    L.push(`  ${ansi.dim(r.path)}`);

    if (r.findings.length === 0) {
      L.push(`    ${severityColor.low('no findings')}`);
    }
    for (const f of r.findings) {
      L.push(severityColor[f.severity](`    [${f.severity.toUpperCase()}] ${f.ruleId} · ${f.title}  ${ansi.dim(`(score ${f.score})`)}`));
      L.push(`        ${ansi.dim('location:')} ${f.location}`);
      L.push(`        ${ansi.dim('evidence:')} ${squash(f.evidence).slice(0, 200)}`);
      if (f.standards.length) {
        L.push(`        ${ansi.dim('standards:')} ${f.standards.map((s) => `${s.id}`).join(', ')}`);
      }
    }

    if (r.ai) {
      L.push(`    ${ansi.magenta('◆ AI review')} ${ansi.dim(`${r.ai.model} · severity ${r.ai.severity} · confidence ${(r.ai.confidence * 100).toFixed(0)}%`)}`);
      L.push(`        ${ansi.dim('intent:')} ${squash(r.ai.intent)}`);
      if (r.ai.manipulationTechniques.length) {
        L.push(`        ${ansi.dim('techniques:')} ${r.ai.manipulationTechniques.join(', ')}`);
      }
      if (r.ai.rationale) {
        L.push(`        ${ansi.dim('why:')} ${squash(r.ai.rationale).slice(0, 240)}`);
      }
    } else if (r.aiError) {
      L.push(`    ${ansi.dim(`◆ AI review unavailable (${r.aiError}) — static findings above are complete`)}`);
    }
    L.push('');
  }

  // Summary
  const bySev = countBySeverity(result);
  const sevLine = SEVERITY_ORDER
    .filter((s) => bySev[s] > 0)
    .map((s) => severityColor[s](`${bySev[s]} ${s}`))
    .join(' · ');
  L.push('  ' + '─'.repeat(66));
  L.push(`  ${result.filesScanned} file(s) scanned · ${totalFindings(result)} finding(s)${sevLine ? ` · ${sevLine}` : ''}${result.aiUsed ? ansi.magenta(' · AI: local open-weight model') : ''}`);
  if (result.skipped.length) {
    L.push(ansi.dim(`  skipped: ${result.skipped.join(', ')}`));
  }
  L.push('');
  return L.join('\n');
}

function totalFindings(result: ScanResult): number {
  return result.reports.reduce((n, r) => n + r.findings.length, 0);
}

export function countBySeverity(result: ScanResult): Record<Severity, number> {
  const out: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const r of result.reports) for (const f of r.findings) out[f.severity]++;
  return out;
}

// ------------------------------------------------------------ markdown ----

export function renderMarkdown(result: ScanResult): string {
  const L: string[] = [];
  L.push('# SkillSentry scan report', '');
  L.push(`- Files scanned: ${result.filesScanned}`);
  L.push(`- AI layer: ${result.aiUsed ? 'local open-weight model' : 'not used'}`);
  L.push(`- Generated: ${new Date().toISOString()}`, '');

  for (const r of result.reports) {
    L.push(`## ${r.name} — verdict: **${r.verdict}** (risk ${r.riskScore}/100)`, '');
    L.push(`Path: \`${r.path}\` · kind: \`${r.kind}\``, '');
    if (r.findings.length === 0) {
      L.push('_No static findings._', '');
    } else {
      L.push('| Severity | Rule | Location | Evidence |', '|---|---|---|---|');
      for (const f of r.findings) {
        L.push(`| ${f.severity} | ${f.ruleId} ${f.title} | \`${f.location}\` | ${mdEscape(squash(f.evidence)).slice(0, 180)} |`);
      }
      L.push('');
    }
    if (r.ai) {
      L.push(`**AI review** (${r.ai.model}): severity ${r.ai.severity}, confidence ${(r.ai.confidence * 100).toFixed(0)}%`, '');
      L.push(`> ${squash(r.ai.rationale)}`, '');
    }
  }
  return L.join('\n');
}

function mdEscape(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}

// ----------------------------------------------------------------- json ----

export function renderJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
