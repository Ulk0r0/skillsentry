import { promises as fs } from 'node:fs';
import path from 'node:path';
import type {
  Finding,
  ScanOptions,
  ScanReport,
  ScanResult,
  ScanSurface,
  ScanTarget,
  Severity,
  Verdict
} from './types.js';
import { severityRank } from './types.js';
import { parseSkillMd, isSkillMdFile } from './parser/skill-md.js';
import { parseMcpConfig, isMcpConfigFile } from './parser/mcp-config.js';
import { rulesFor } from './rules/index.js';
import { applySuppressions } from './suppress.js';
import { assessWithAi, probeAi, DEFAULT_AI_BASE_URL, DEFAULT_MODEL } from './ai.js';

/** Deterministic, offline core. The AI layer is additive and optional. */

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.venv', 'coverage']);
const MAX_FILES = 500;
const MAX_MATCHES_PER_RULE = 12;
// A SKILL.md or MCP config is documentation-scale. Anything far beyond that
// (minified dumps, logs, accidental secret stores) is a memory hazard for a
// local tool that reads everything it is pointed at — refuse it with an
// explicit skip instead of buffering it whole. Exported so integrators can
// mirror the same bound before handing strings to scanText.
export const MAX_FILE_BYTES = 2 * 1024 * 1024;

// ------------------------------------------------------------ discovery ----

async function collectFiles(inputs: string[], skipped: string[], log?: (m: string) => void): Promise<string[]> {
  const files = new Set<string>();
  for (const input of inputs) {
    let st;
    try {
      st = await fs.stat(input);
    } catch {
      skipped.push(input);
      log?.(`skipped (does not exist or unreadable): ${input}`);
      continue;
    }
    if (st.isFile()) {
      if (isCandidate(input)) files.add(path.resolve(input));
      else {
        skipped.push(input);
        log?.(`skipped (not a SKILL.md / MCP config candidate): ${input}`);
      }
    } else if (st.isDirectory()) {
      await walk(input, files, 0);
    }
  }
  return [...files].sort();
}

async function walk(dir: string, out: Set<string>, depth: number): Promise<void> {
  if (depth > 8 || out.size >= MAX_FILES) return;
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (out.size >= MAX_FILES) return;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) await walk(full, out, depth + 1);
    } else if (e.isFile() && isCandidate(e.name)) {
      out.add(path.resolve(full));
    }
  }
}

function isCandidate(fileName: string): boolean {
  return isSkillMdFile(fileName) || isMcpConfigFile(fileName);
}

// -------------------------------------------------------------- parsing ----

export function parseTarget(filePath: string, raw: string): ScanTarget {
  const base = path.basename(filePath);
  if (isSkillMdFile(base)) return parseSkillMd(filePath, raw);
  if (isMcpConfigFile(base)) return parseMcpConfig(filePath, raw);
  // Unknown extension: treat as skill markdown (best effort, never throws).
  return parseSkillMd(filePath, raw);
}

// ------------------------------------------------------ static analysis ----

export function runStaticRules(target: ScanTarget): Finding[] {
  const findings: Finding[] = [];
  for (const rule of rulesFor(target.kind)) {
    let matches = 0;
    for (const surface of target.surfaces) {
      for (const raw of rule.run(surface, target)) {
        if (matches >= MAX_MATCHES_PER_RULE) break;
        matches++;
        findings.push({
          ruleId: rule.id,
          title: rule.title,
          description: rule.description + (raw.note ? `\n\nDetail: ${raw.note}` : ''),
          severity: raw.severity ?? rule.severity,
          score: raw.score ?? rule.score,
          evidence: raw.evidence,
          location: surface.location,
          remediation: rule.remediation,
          standards: rule.standards
        });
      }
      if (matches >= MAX_MATCHES_PER_RULE) break;
    }
  }
  return findings.sort((a, b) => b.score - a.score || a.ruleId.localeCompare(b.ruleId));
}

// ------------------------------------------------------------- scoring ----

export function aggregateRisk(findings: Finding[]): { riskScore: number; verdict: Verdict } {
  if (findings.length === 0) return { riskScore: 0, verdict: 'clean' };
  const scores = findings.map((f) => f.score).sort((a, b) => b - a);
  const max = scores[0] ?? 0;
  const breadth = Math.min(30, (scores.length - 1) * 4);
  const riskScore = Math.min(100, Math.round(max * 6.5 + breadth));
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const worst = findings.reduce<Severity>((acc, f) => (severityRank(f.severity) > severityRank(acc) ? f.severity : acc), 'info');
  // A CLEAN badge next to a listed finding is a contradiction a reviewer
  // would rightly distrust — any low-or-above finding makes the report at
  // least suspicious. info-only reports stay clean (no rule emits info today;
  // the level exists for library integrations).
  const hasLowOrAbove = findings.some((f) => severityRank(f.severity) >= severityRank('low'));

  const verdict: Verdict =
    hasCritical || riskScore >= 60 ? 'dangerous'
    : worst === 'medium' || worst === 'high' || riskScore >= 30 || hasLowOrAbove ? 'suspicious'
    : 'clean';
  return { riskScore, verdict };
}

// --------------------------------------------------------------- scan ----

export async function scanText(
  fileName: string,
  content: string,
  opts: ScanOptions = {}
): Promise<ScanReport> {
  const started = Date.now();
  const target = parseTarget(fileName, content);
  const staticFindings = runStaticRules(target);
  // Inline suppressions with a mandatory reason; suppressed items stay in
  // the report for audit, scoring/verdict use only the kept findings.
  const { kept, suppressed } = applySuppressions(staticFindings, content);
  const { riskScore, verdict } = aggregateRisk(kept);

  const report: ScanReport = {
    path: target.path,
    kind: target.kind,
    name: target.name,
    findings: kept,
    suppressed: suppressed.length > 0 ? suppressed : undefined,
    riskScore,
    verdict,
    ai: null,
    scannedAt: new Date().toISOString(),
    durationMs: 0
  };

  if (opts.ai !== false && target.surfaces.length > 0) {
    try {
      report.ai = await assessWithAi(target, opts);
    } catch (err) {
      report.aiError = err instanceof Error ? err.message : String(err);
    }
  }

  report.durationMs = Date.now() - started;
  return report;
}

export async function scanPaths(inputs: string[], opts: ScanOptions = {}): Promise<ScanResult> {
  const skipped: string[] = [];
  const files = await collectFiles(inputs, skipped, opts.log);

  let aiAvailable = false;
  if (opts.ai !== false && files.length > 0) {
    if (opts.aiForce) {
      // --ai means intent: skip the 1.5s probe gate and let assessWithAi try.
      // A dead endpoint still degrades gracefully (per-file aiError), it just
      // costs the per-target timeout instead of a fast probe refusal.
      aiAvailable = true;
    } else {
      aiAvailable = await probeAi(opts.openaiBaseUrl ?? DEFAULT_AI_BASE_URL);
      if (!aiAvailable) {
        opts.log?.(`no local OpenAI-compatible runtime at ${opts.openaiBaseUrl ?? DEFAULT_AI_BASE_URL} — static-only scan`);
      }
    }
  }

  const reports: ScanReport[] = [];
  const scanStarted = Date.now();
  for (const file of files) {
    // Re-stat before reading: collect ran a while ago, and a file swapped
    // for a directory (or grown pathologically) must not crash or OOM the
    // scan — it gets the same explicit skip treatment as missing inputs.
    const st = await fs.stat(file).catch(() => null);
    if (!st || !st.isFile()) {
      skipped.push(file);
      opts.log?.(`skipped (unreadable): ${file}`);
      continue;
    }
    if (st.size > MAX_FILE_BYTES) {
      skipped.push(file);
      opts.log?.(`skipped (exceeds ${MAX_FILE_BYTES}-byte cap): ${file}`);
      continue;
    }
    let raw: string;
    try {
      raw = await fs.readFile(file, 'utf8');
    } catch {
      skipped.push(file);
      opts.log?.(`skipped (read error): ${file}`);
      continue;
    }
    const reportOpts: ScanOptions = aiAvailable ? opts : { ...opts, ai: false };
    reports.push(await scanText(file, raw, reportOpts));
  }

  const result: ScanResult = {
    reports,
    filesScanned: reports.length,
    skipped,
    aiUsed: reports.some((r) => r.ai !== null),
    durationTotalMs: Date.now() - scanStarted
  };
  return result;
}

// Re-exports so consumers (CLI/dashboard) only import from the root.
export { DEFAULT_AI_BASE_URL, DEFAULT_MODEL };
export type { ScanSurface };
