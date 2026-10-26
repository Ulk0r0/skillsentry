/**
 * Inline suppressions with a mandatory reason — the ESLint escape hatch,
 * made explicit for security findings.
 *
 *   <!-- skillsentry-ignore SS-003 SS-007: documented credential reader used
 *        by the user-approved backup workflow -->
 *
 * Design invariants:
 * - A suppression without at least one valid rule id or without a reason is
 *   ignored (silent `<!-- skillsentry-ignore: because -->` must not become a
 *   blank check).
 * - Suppressions are file-level and apply to every finding of the named
 *   rules; the suppressed items stay visible in the report (`suppressed`),
 *   so the mechanism can never be a silent hole.
 * - Parsing is deterministic: comments are processed in textual order and
 *   the first covering suppression wins for a given finding.
 */

import type { Finding, SuppressedFinding } from './types.js';
import { allMatches } from './util/text.js';

export type { SuppressedFinding } from './types.js';

export interface Suppression {
  ruleIds: string[];
  reason: string;
}

const IGNORE_COMMENT = /<!--\s*skillsentry-ignore\s+([^:]*?)\s*:\s*([\s\S]*?)-->/gi;
const RULE_ID = /SS-\d{3}/gi;

/** Parse every well-formed ignore comment, in textual order. */
export function parseSuppressions(text: string): Suppression[] {
  const out: Suppression[] = [];
  for (const m of allMatches(IGNORE_COMMENT, text)) {
    const idsBlob = m[1] ?? '';
    const reason = (m[2] ?? '').replace(/\s+/g, ' ').trim();
    if (!reason) continue;
    const ruleIds = [...new Set([...idsBlob.matchAll(new RegExp(RULE_ID.source, RULE_ID.flags))].map((r) => (r[0] ?? '').toUpperCase()))];
    if (ruleIds.length === 0) continue;
    out.push({ ruleIds, reason });
  }
  return out;
}

/**
 * Split findings into kept and suppressed. Suppression is file-level: one
 * comment silences every match of its named rules in this file, and each
 * suppressed finding carries the winning reason for the audit trail.
 */
export function applySuppressions(
  findings: Finding[],
  text: string
): { kept: Finding[]; suppressed: SuppressedFinding[] } {
  const suppressions = parseSuppressions(text);
  if (suppressions.length === 0 || findings.length === 0) {
    return { kept: findings, suppressed: [] };
  }
  const kept: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const finding of findings) {
    const cover = suppressions.find((s) => s.ruleIds.includes(finding.ruleId));
    if (cover) suppressed.push({ ruleId: finding.ruleId, reason: cover.reason, evidence: finding.evidence });
    else kept.push(finding);
  }
  return { kept, suppressed };
}
