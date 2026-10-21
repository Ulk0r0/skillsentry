import { defineConfig } from 'vitest/config';

export default defineConfig({
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
