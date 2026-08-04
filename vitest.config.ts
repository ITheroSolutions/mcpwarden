import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts', 'src/**/*.test.ts'],
    environment: 'node',

    // Protocol tests spawn child processes and bind local sockets. A generous
    // per test timeout keeps a slow Windows CI runner from producing flakes,
    // while the hang tests set their own much shorter budgets explicitly.
    testTimeout: 20_000,
    hookTimeout: 20_000,

    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/index.ts', 'src/**/*.test.ts', 'src/types/**'],

      // Thresholds are set to what this suite actually meets and are raised as
      // phases land. A threshold that is routinely lowered teaches nothing.
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80,
      },
    },
  },
});
