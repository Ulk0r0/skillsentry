#!/usr/bin/env node
/**
 * Generate a SARIF 2.1.0 report over SkillSentry's own source and write it
 * to `skillsentry.sarif` in the current working directory (the repo root in
 * CI). samples/ is deliberately NOT scanned here: its poisoned fixtures are
 * intentional attack material for tests — they would create permanent
 * Code Scanning alerts instead of guarding the real code.
 *
 * Run from the repo root:  node packages/skillsentry/scripts/self-sarif.mjs
 */
import { writeFileSync } from 'node:fs';
import { scanPaths, renderSarif } from '../dist/index.js';

const result = await scanPaths(['packages', 'apps'], { ai: false });
const sarif = renderSarif(result, { root: process.cwd() });
writeFileSync('skillsentry.sarif', sarif + '\n');
const findings = result.reports.reduce((n, r) => n + r.findings.length, 0);
console.log(`skillsentry.sarif written — ${result.filesScanned} file(s) scanned, ${findings} finding(s)`);
