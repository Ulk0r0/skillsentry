/**
 * SkillSentry core types.
 *
 * A `Finding` is one rule match against one target. `ScanReport` is the
 * aggregate for a single target (file). `ScanResult` bundles the reports for
 * a whole `scan()` invocation.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/**
 * Reference to a published threat-categorization framework.
 * `id` uses the official identifier when one exists (OWASP LLM Top 10 2026
 * uses LLM01..LLM10). For frameworks without a stable public per-item ID at
 * the time of writing (AST10, OWASP MCP Top 10) we emit a stable informal
 * slug and point `url` at the official project so readers can verify.
 */
export interface StandardRef {
  framework: 'OWASP LLM Top 10 (2026)' | 'AST10' | 'OWASP MCP Top 10';
  /** Official id when available, otherwise a stable informal slug. */
  id: string;
  name: string;
  url?: string;
}

export type TargetKind = 'skill-md' | 'mcp-config';

export interface ScanTarget {
  /** Absolute or CLI-given path of the scanned file. */
  path: string;
  kind: TargetKind;
  /** Skill name (SKILL.md frontmatter) or MCP config file name. */
  name: string;
  /** Structured surface the rules evaluate, per target kind. */
  surfaces: ScanSurface[];
}

export interface ScanSurface {
  /** e.g. "frontmatter.description", "body", "mcpServers.filesystem" */
  location: string;
  /** The exact text the rules run against. */
  text: string;
  /** Optional short human label (e.g. the MCP server name). */
  label?: string;
}

export interface Finding {
  /** Rule id, e.g. "SS-001". */
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  /** 0..10, calibrated per rule. */
  score: number;
  /** Short quoted snippet proving the match. */
  evidence: string;
  /** Where in the target the match happened. */
  location: string;
  /** What the author/maintainer should do instead. */
  remediation: string;
  standards: StandardRef[];
}

export interface AiAssessment {
  provider: string;
  model: string;
  intent: string;
  manipulationTechniques: string[];
  dataFlows: string;
  severity: Severity;
  confidence: number;
  rationale: string;
  standards: StandardRef[];
}

export type Verdict = 'clean' | 'suspicious' | 'dangerous';

/**
 * A finding matched a `<!-- skillsentry-ignore SS-xxx: reason -->` comment
 * and was excluded from scoring. Kept in the report so suppressions can
 * never become a silent hole.
 */
export interface SuppressedFinding {
  ruleId: string;
  reason: string;
  evidence: string;
}

export interface ScanReport {
  path: string;
  kind: TargetKind;
  name: string;
  findings: Finding[];
  /** Findings excluded by inline ignore comments (audit trail). */
  suppressed?: SuppressedFinding[];
  /** 0..100 aggregate risk. */
  riskScore: number;
  verdict: Verdict;
  ai: AiAssessment | null;
  aiError?: string;
  scannedAt: string;
  durationMs: number;
}

export interface ScanResult {
  reports: ScanReport[];
  filesScanned: number;
  skipped: string[];
  aiUsed: boolean;
  /** Total wall-clock time for the whole scan (all targets). */
  durationTotalMs?: number;
}

export interface ScanOptions {
  /** Force the AI layer on/off. Default: on when a local runtime answers. */
  ai?: boolean;
  /** OpenAI-compatible endpoint (llama.cpp server, LM Studio, vLLM...). */
  openaiBaseUrl?: string;
  /** Model identifier, e.g. "llama3.2:3b" (Ollama) — open-weight models. */
  model?: string;
  /** AI request timeout in ms. Default 20000. */
  aiTimeoutMs?: number;
  /** Fail (exit code) threshold for CI usage. */
  failOn?: Severity;
  /** Logger for diagnostics. */
  log?: (msg: string) => void;
}

export const STANDARD_URLS = {
  llmTop10: 'https://genai.owasp.org/Top-10-2026/',
  ast10: 'https://github.com/OWASP/www-project-agentic-skills-top-10',
  mcpTop10: 'https://github.com/OWASP-MCP-Governance-and-Risk-Project/docs'
} as const;
