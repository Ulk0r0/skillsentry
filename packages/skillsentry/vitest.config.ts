import { defineConfig } from 'vitest/config';

export default defineConfig({
  // This package can be checked out nested inside another project whose root
  // carries a PostCSS config (e.g. a Next.js site). Vite's postcss loader
  // walks up and chokes on it — disable stylesheet handling entirely; a
  // static-analysis CLI has no CSS to transform.
  css: { postcss: { plugins: [] } },
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 20000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.d.ts', 'src/index.ts', 'src/rules/rule.ts'],
      thresholds: {
        // Enforced in CI. Raised deliberately when coverage grows; failing
        // builds are how this number stays honest.
        lines: 85,
        functions: 85,
        branches: 75,
        statements: 85
      }
    }
  }
});
