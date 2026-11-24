import { defineConfig, devices } from '@playwright/test'

/**
 * Product UI performance gate — Chromium smoke over multi-MiB logs.
 * Separate from spike harness — serves production preview of the real SPA.
 */
export default defineConfig({
  testDir: './tests/performance/e2e',
  testMatch: '**/text-product-perf.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 20 * 60 * 1000,
  expect: { timeout: 180_000 },
  reporter: [['list'], ['json', { outputFile: 'tests/performance/results/product-ui-report.json' }]],
  webServer: {
    command: 'npm run build && npm run preview -- --host 127.0.0.1 --port 4174',
    url: 'http://127.0.0.1:4174/',
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:4174',
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
