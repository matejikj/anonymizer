import { defineConfig, devices } from '@playwright/test'

/**
 * Baseline browser performance gate — diagnostics hook + multi-MiB smoke.
 * Full 90/100 MiB scenarios run here, not in default `npm test`.
 */
export default defineConfig({
  testDir: './tests/performance/e2e',
  testMatch: '**/baseline-*.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 45 * 60 * 1000,
  expect: { timeout: 300_000 },
  reporter: [
    ['list'],
    ['json', { outputFile: 'tests/performance/results/baseline-ui-report.json' }],
  ],
  webServer: {
    command: 'npm run build && npm run preview -- --host 127.0.0.1 --port 4175',
    url: 'http://127.0.0.1:4175/',
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:4175',
    trace: 'off',
    video: 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        channel: 'chrome',
      },
    },
  ],
})
