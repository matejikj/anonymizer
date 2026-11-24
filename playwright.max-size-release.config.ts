import { defineConfig } from '@playwright/test'
import { releaseBrowserProjects, RELEASE_RESULTS_DIR } from './playwright.browserProjects.ts'

const preview = 'npm run preview -- --host 127.0.0.1 --port 4176'
// Opt-in only: auto-skipping when dist/ exists left the gate on stale bundles (R10).
const skipBuild = process.env.MAX_SIZE_SKIP_BUILD === '1'
const webServerCommand = skipBuild ? preview : `npm run build && ${preview}`

/**
 * Max-size release gate — tri-browser text/PCAP performance and core checks.
 * Full 90/100 MiB scenarios require `npm run fixtures:max-size` and MAX_SIZE_FULL=1.
 */
export default defineConfig({
  testDir: './tests/performance/e2e',
  testMatch: '**/max-size-*.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 50 * 60 * 1000,
  expect: { timeout: 300_000 },
  reporter: [
    ['list'],
    ['json', { outputFile: `${RELEASE_RESULTS_DIR}/max-size-ui-report.json` }],
  ],
  webServer: {
    command: webServerCommand,
    url: 'http://127.0.0.1:4176/',
    reuseExistingServer: !process.env.CI,
    timeout: 300_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:4176',
    trace: 'off',
    video: 'off',
  },
  projects: releaseBrowserProjects(),
})
