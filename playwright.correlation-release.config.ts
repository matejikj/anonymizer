import { defineConfig } from '@playwright/test'
import { releaseBrowserProjects, RELEASE_RESULTS_DIR } from './playwright.browserProjects.ts'

/**
 * Correlation release gate — tri-browser import / review / export / lookup.
 * Micro fixtures by default; does not ship mapping bundles or originals in reports.
 */
export default defineConfig({
  testDir: './tests/performance/e2e',
  testMatch: '**/correlation-*.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 15 * 60 * 1000,
  expect: { timeout: 120_000 },
  reporter: [
    ['list'],
    ['json', { outputFile: `${RELEASE_RESULTS_DIR}/correlation-ui-report.json` }],
  ],
  webServer: {
    command: 'npm run build && npm run preview -- --host 127.0.0.1 --port 4177',
    url: 'http://127.0.0.1:4177/',
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:4177',
    trace: 'off',
    video: 'off',
  },
  projects: releaseBrowserProjects(),
})
