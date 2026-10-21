#!/usr/bin/env node
/**
 * SkillSentry benchmark — scans the bundled sample gallery repeatedly and
 * reports wall-clock throughput. The workload is fixed (same samples every
 * run) and the scan is deterministic, so numbers are comparable across
 * commits. AI layer disabled: this measures the static engine.
 *
 *   npm run bench
 */
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { scanPaths } from '../dist/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const samples = path.resolve(here, '../../../samples');

const WARMUP = 2;
const RUNS = 12;

async function main() {
  const reference = await scanPaths([samples], { ai: false });
  for (let i = 0; i < WARMUP; i++) await scanPaths([samples], { ai: false });

  const times = [];
  for (let i = 0; i < RUNS; i++) {
    const t0 = performance.now();
    const r = await scanPaths([samples], { ai: false });
    times.push(performance.now() - t0);
    if (r.filesScanned !== reference.filesScanned) {
      throw new Error(`workload drifted: ${r.filesScanned} vs ${reference.filesScanned} files`);
    }
  }

  times.sort((a, b) => a - b);
  const median = times[Math.floor(times.length / 2)] ?? 0;
  const best = times[0] ?? 0;
  const worst = times[times.length - 1] ?? 0;
  console.log(`SkillSentry benchmark — ${reference.filesScanned} files, static rules only, ${RUNS} runs`);
  console.log(`  median ${median.toFixed(1)} ms/run · best ${best.toFixed(1)} ms · worst ${worst.toFixed(1)} ms`);
  console.log(`  throughput ~${Math.round((reference.filesScanned / median) * 1000)} files/s`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
