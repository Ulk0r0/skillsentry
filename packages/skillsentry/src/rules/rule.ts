import type { ScanSurface, ScanTarget, Severity, StandardRef } from '../types.js';

/**
 * A static rule evaluates one `ScanSurface` and returns raw matches that the
 * engine converts into `Finding`s. Rules are pure functions: no I/O, no
 * randomness, fully unit-testable.
 */
export interface Rule {
  id: string;
  title: string;
  description: string;
  remediation: string;
  /** Baseline severity/score; individual matches may override. */
  severity: Severity;
  score: number;
  standards: StandardRef[];
  /** Target kinds this rule applies to. */
  appliesTo: Array<'skill-md' | 'mcp-config'>;
  run(surface: ScanSurface, target: ScanTarget): RawMatch[];
}

export interface RawMatch {
  evidence: string;
  /** Extra context appended to the finding description. */
  note?: string;
  severity?: Severity;
  score?: number;
}
