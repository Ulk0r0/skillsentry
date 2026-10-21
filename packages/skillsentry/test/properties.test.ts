/**
 * Property-based tests (fast-check, dev-only dependency).
 *
 * Unit tests pin known examples; properties pin invariants that must hold
 * for EVERY input — the right tool for a scanner whose input is untrusted
 * text: parsing never throws, JSONC stripping never corrupts valid JSON,
 * scoring stays in its documented range, suppressions never leak.
 */
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { parseSkillMd } from '../src/parser/skill-md.js';
import { parseMcpConfig, stripJsonc } from '../src/parser/mcp-config.js';
import { aggregateRisk } from '../src/scanner.js';
import { applySuppressions } from '../src/suppress.js';
import type { Finding, Severity, Verdict } from '../src/types.js';

const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
const VERDICTS: Verdict[] = ['clean', 'suspicious', 'dangerous'];

describe('property: parsers never throw on untrusted text', () => {
  it('parseSkillMd survives arbitrary strings', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 2000 }), (raw) => {
        expect(() => parseSkillMd('SKILL.md', raw)).not.toThrow();
      }),
      { numRuns: 300 }
    );
  });

  it('parseMcpConfig survives arbitrary strings', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 2000 }), (raw) => {
        expect(() => parseMcpConfig('claude_desktop_config.json', raw)).not.toThrow();
      }),
      { numRuns: 300 }
    );
  });
});

describe('property: stripJsonc preserves valid JSON exactly', () => {
  it('round-trips any JSON value, including strings full of // and /*', () => {
    fc.assert(
      fc.property(fc.jsonValue({ depthSize: 'small' }), (value) => {
        const json = JSON.stringify(value);
        const stripped = stripJsonc(json);
        // Compare by canonical re-serialization, not deep equality: JSON
        // itself does not distinguish -0 from 0 (JSON.stringify(-0) is "0"),
        // so an Object.is-based deep equal would fail on JSON's own limits,
        // not on stripJsonc. Canonical comparison is the stricter, honest
        // form of "the stripper does not change the meaning".
        expect(JSON.stringify(JSON.parse(stripped))).toBe(json);
      }),
      { numRuns: 300 }
    );
  });

  it('never throws on arbitrary text', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 2000 }), (raw) => {
        expect(() => stripJsonc(raw)).not.toThrow();
      }),
      { numRuns: 300 }
    );
  });
});

describe('property: aggregateRisk stays in its documented contract', () => {
  const findingArb = fc
    .record({
      severity: fc.constantFrom(...SEVERITIES),
      score: fc.integer({ min: 0, max: 10 })
    })
    .map((p) => p as unknown as Finding);

  it('risk is 0..100 and the verdict is a known level', () => {
    fc.assert(
      fc.property(fc.array(findingArb, { maxLength: 30 }), (findings) => {
        const { riskScore, verdict } = aggregateRisk(findings);
        expect(riskScore).toBeGreaterThanOrEqual(0);
        expect(riskScore).toBeLessThanOrEqual(100);
        expect(VERDICTS).toContain(verdict);
      }),
      { numRuns: 300 }
    );
  });

  it('no findings means clean and risk 0', () => {
    const { riskScore, verdict } = aggregateRisk([]);
    expect(riskScore).toBe(0);
    expect(verdict).toBe('clean');
  });

  it('a critical finding always yields dangerous', () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { maxLength: 30 }),
        fc.integer({ min: 1, max: 10 }),
        (rest, criticalScore) => {
          const findings: Finding[] = [
            { ...({ severity: 'critical', score: criticalScore } as unknown as Finding) },
            ...rest
          ];
          expect(aggregateRisk(findings).verdict).toBe('dangerous');
        }
      ),
      { numRuns: 200 }
    );
  });
});

describe('property: suppressions never leak named rules', () => {
  const ruleIdArb = fc.constantFrom('SS-001', 'SS-003', 'SS-007', 'SS-010', 'SS-011');
  const findingArb = fc
    .record({
      ruleId: ruleIdArb,
      severity: fc.constantFrom(...SEVERITIES),
      score: fc.integer({ min: 0, max: 10 })
    })
    .map((p) => p as unknown as Finding);

  it('every finding covered by an ignore comment is absent from kept', () => {
    fc.assert(
      fc.property(
        fc.array(findingArb, { maxLength: 20 }),
        ruleIdArb,
        fc.string({ maxLength: 60 }).filter((s) => !s.includes('-->') && s.trim().length > 0),
        (findings, id, reason) => {
          const text = `<!-- skillsentry-ignore ${id}: ${reason} -->`;
          const { kept, suppressed } = applySuppressions(findings, text);
          expect(kept.every((f) => f.ruleId !== id)).toBe(true);
          expect(suppressed.every((s) => s.ruleId === id)).toBe(true);
          expect(kept.length + suppressed.length).toBe(findings.length);
        }
      ),
      { numRuns: 300 }
    );
  });
});
