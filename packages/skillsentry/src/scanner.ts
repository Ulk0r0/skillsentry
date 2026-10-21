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
import { assessWithAi, probeAi, DEFAULT_AI_BASE_URL, DEFAULT_MODEL } from './ai.js';

/** Deterministic, offline core. The AI layer is additive and optional. */

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.venv', 'coverage']);
const MAX_FILES = 500;
const MAX_MATCHES_PER_RULE = 12;

// ------------------------------------------------------------ discovery ----

async function collectFiles(inputs: string[], skipped: string[]): Promise<string[]> {
  const files = new Set<string>();
  for (const input of inputs) {
    let st;
    try {
      st = await fs.stat(input);
    } catch {
      skipped.push(input);
      continue;
    }
    if (st.isFile()) {
      if (isCandidate(input)) files.add(path.resolve(input));
      else skipped.push(input);
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
  const max = scores[0];
  const breadth = Math.min(30, (scores.length - 1) * 4);
  const riskScore = Math.min(100, Math.round(max * 6.5 + breadth));
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const worst = findings.reduce<Severity>((acc, f) => (severityRank(f.severity) > severityRank(acc) ? f.severity : acc), 'info');

  const verdict: Verdict =
    hasCritical || riskScore >= 60 ? 'dangerous'
    : worst === 'medium' || worst === 'high' || riskScore >= 30 ? 'suspicious'
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
  const findings = runStaticRules(target);
  const { riskScore, verdict } = aggregateRisk(findings);

  const report: ScanReport = {
    path: target.path,
    kind: target.kind,
    name: target.name,
    findings,
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
  const files = await collectFiles(inputs, skipped);
  const started = Date.now();
  void started;

  let aiAvailable = false;
  if (opts.ai !== false && files.length > 0) {
    aiAvailable = await probeAi(opts.openaiBaseUrl ?? DEFAULT_AI_BASE_URL);
    if (!aiAvailable) {
      opts.log?.(`no local OpenAI-compatible runtime at ${opts.openaiBaseUrl ?? DEFAULT_AI_BASE_URL} — static-only scan`);
    }
  }

  const reports: ScanReport[] = [];
  const scanStarted = Date.now();
  for (const file of files) {
    let raw: string;
    try {
      raw = await fs.readFile(file, 'utf8');
    } catch {
      skipped.push(file);
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
