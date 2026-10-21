import type { Finding, ScanResult, Severity, TargetKind, Verdict } from './types.js';
import { severityRank } from './types.js';
import { ansi, severityColor, squash } from './util/text.js';

/**
 * Rug-pull detection: compare two scans of the same skill/config set and
 * surface what CHANGED, not just what is. The classic supply-chain attack on
 * agents (OWASP MCP Top 10: tool rug-pull) installs a benign version, earns
 * trust, then updates itself into something poisonous. A one-shot scanner
 * never sees that transition — a diff does.
 *
 * Reports are matched semantically (kind + name), so the two snapshots may
 * live in different directories (e.g. yesterday's backup vs today's install).
 * Findings are matched by (ruleId, location, severity): the same rule firing
 * on the same surface at the same severity is the same finding, even if the
 * attacker reworded the sentence — that is exactly the update case we must
 * not miss.
 */

export interface DiffEntry {
  kind: TargetKind;
  name: string;
  /** Path in the OLD snapshot; null → file appeared in the new snapshot. */
  oldPath: string | null;
  /** Path in the NEW snapshot; null → file removed since the old snapshot. */
  newPath: string | null;
  oldVerdict: Verdict | null;
  newVerdict: Verdict | null;
  oldRisk: number | null;
  newRisk: number | null;
  /** Findings present in new but absent in old — the rug-pull signal. */
  added: Finding[];
  /** Findings present in old but resolved in new (e.g. a cleaned version). */
  removed: Finding[];
  /** How many findings stayed identical between snapshots. */
  unchanged: number;
}

export interface DiffResult {
  entries: DiffEntry[];
  totalAdded: number;
  totalRemoved: number;
  /** Highest severity among added findings, or null when nothing is new. */
  maxAddedSeverity: Severity | null;
}

function reportKey(kind: TargetKind, name: string): string {
  return `${kind}\u0000${name}`;
}

function findingKey(f: Finding): string {
  return `${f.ruleId}\u0000${f.location}\u0000${f.severity}`;
}

/** Pure and deterministic: identical inputs always produce identical diffs. */
export function diffResults(oldResult: ScanResult, newResult: ScanResult): DiffResult {
  const oldByKey = new Map(oldResult.reports.map((r) => [reportKey(r.kind, r.name), r]));
  const newByKey = new Map(newResult.reports.map((r) => [reportKey(r.kind, r.name), r]));
  const keys = [...new Set([...oldByKey.keys(), ...newByKey.keys()])].sort();

  const entries: DiffEntry[] = keys.map((key) => {
    const oldR = oldByKey.get(key);
    const newR = newByKey.get(key);
    const kind: TargetKind = (oldR ?? newR)!.kind;
    const name: string = (oldR ?? newR)!.name;

    if (!oldR || !newR) {
      // File appeared or disappeared: every finding on the live side is new
      // (or resolved) — never silently drop them.
      const live = (newR ?? oldR)!.findings;
      return {
        kind,
        name,
        oldPath: oldR?.path ?? null,
        newPath: newR?.path ?? null,
        oldVerdict: oldR?.verdict ?? null,
        newVerdict: newR?.verdict ?? null,
        oldRisk: oldR?.riskScore ?? null,
        newRisk: newR?.riskScore ?? null,
        added: newR ? live : [],
        removed: oldR ? live : [],
        unchanged: 0
      };
    }

    const oldKeys = new Set(oldR.findings.map(findingKey));
    const newKeys = new Set(newR.findings.map(findingKey));
    const added = newR.findings.filter((f) => !oldKeys.has(findingKey(f)));
    const removed = oldR.findings.filter((f) => !newKeys.has(findingKey(f)));
    const unchanged = oldR.findings.length - removed.length;

    return {
      kind,
      name,
      oldPath: oldR.path,
      newPath: newR.path,
      oldVerdict: oldR.verdict,
      newVerdict: newR.verdict,
      oldRisk: oldR.riskScore,
      newRisk: newR.riskScore,
      added,
      removed,
      unchanged
    };
  });

  const allAdded = entries.flatMap((e) => e.added);
  const maxAddedSeverity: Severity | null = allAdded.length
    ? allAdded.reduce<Severity>((acc, f) => (severityRank(f.severity) > severityRank(acc) ? f.severity : acc), 'info')
    : null;

  return {
    entries,
    totalAdded: allAdded.length,
    totalRemoved: entries.reduce((n, e) => n + e.removed.length, 0),
    maxAddedSeverity
  };
}

/**
 * CI gate for the diff: exit 1 when the NEW snapshot introduces findings at
 * or above `failOn`. Resolved findings and pre-existing ones never fail —
 * only a rug-pull does.
 */
export function exitCodeForDiff(diff: DiffResult, failOn: Severity = 'high'): number {
  if (!diff.maxAddedSeverity) return 0;
  return severityRank(diff.maxAddedSeverity) >= severityRank(failOn) ? 1 : 0;
}

// ------------------------------------------------------------ rendering ----

function severityTag(f: Finding): string {
  return severityColor[f.severity](`[${f.severity.toUpperCase()}] ${f.ruleId} · ${f.title}`);
}

export function renderDiffTerminal(diff: DiffResult): string {
  const L: string[] = [];
  L.push('');
  L.push(ansi.bold('  SkillSentry diff') + ansi.dim(' — what changed between the two snapshots'));
  L.push('');

  const interesting = diff.entries.filter((e) => e.added.length || e.removed.length || e.oldPath === null || e.newPath === null);
  if (interesting.length === 0) {
    L.push(`  ${severityColor.low('no changes in security posture — both snapshots scan identically')}`);
  }
  for (const e of interesting) {
    const transition =
      e.oldVerdict === null ? ansi.dim('new file')
      : e.newVerdict === null ? ansi.dim('file removed')
      : `${ansi.dim('verdict')} ${e.oldVerdict} → ${e.newVerdict}  ${ansi.dim('risk')} ${e.oldRisk} → ${e.newRisk}`;
    L.push(`  ${ansi.bold(e.name)} ${ansi.dim(`(${e.kind})`)}  ${transition}`);
    for (const f of e.added) {
      L.push(`    ${ansi.bold('+')} ${severityTag(f)}  ${ansi.dim(`(${f.location})`)}`);
      L.push(`        ${ansi.dim('evidence:')} ${squash(f.evidence).slice(0, 160)}`);
    }
    for (const f of e.removed) {
      L.push(`    ${ansi.dim('-')} ${ansi.dim(`[${f.severity.toUpperCase()}] ${f.ruleId} · ${f.title} (resolved)`)}`);
    }
    if (e.unchanged > 0) {
      L.push(ansi.dim(`    = ${e.unchanged} unchanged finding(s)`));
    }
    L.push('');
  }

  const worst = diff.maxAddedSeverity
    ? severityColor[diff.maxAddedSeverity](diff.maxAddedSeverity.toUpperCase())
    : 'none';
  L.push('  ' + '─'.repeat(66));
  L.push(`  ${diff.totalAdded} new finding(s) · ${diff.totalRemoved} resolved · worst new: ${worst}`);
  L.push('');
  return L.join('\n');
}

export function renderDiffJson(diff: DiffResult): string {
  return JSON.stringify(diff, null, 2);
}
