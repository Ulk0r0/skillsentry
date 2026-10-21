/**
 * SkillSentry — public API surface.
 *
 * Library use:
 *   import { scanPaths, scanText } from 'skillsentry';
 */
export { scanPaths, scanText, parseTarget, runStaticRules, aggregateRisk } from './scanner.js';
export { DEFAULT_AI_BASE_URL, DEFAULT_MODEL, probeAi, assessWithAi, parseAssessment } from './ai.js';
export { renderTerminal, renderMarkdown, renderJson, exitCodeFor, countBySeverity } from './report.js';
export { renderSarif, type SarifOptions } from './report-sarif.js';
export { diffResults, exitCodeForDiff, renderDiffTerminal, renderDiffJson, type DiffResult, type DiffEntry } from './diff.js';
export { ALL_RULES, RULES_BY_ID, rulesFor } from './rules/index.js';
export * from './types.js';
