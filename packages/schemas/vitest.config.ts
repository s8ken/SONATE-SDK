import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Only run the TypeScript source tests. Never pick up compiled artifacts
    // that may linger under dist/ from a `tsc` build.
    include: ['src/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
  },
});
