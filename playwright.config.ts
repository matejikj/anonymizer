import { defineConfig } from '@playwright/test'
import { releaseBrowserProjects } from './playwright.browserProjects.ts'

/**
 * Product e2e. Performance spike suites use playwright.performance.config.ts.
 * Max-size release gate uses playwright.max-size-release.config.ts.
 */
export default defineConfig({
  testDir: './tests/e2e',
  testIgnore: ['**/design-system-gallery.spec.ts'],
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  webServer: {
    command: 'npm run build && npm run preview -- --host 127.0.0.1 --port 4176',
    url: 'http://127.0.0.1:4176/',
    reuseExistingServer: false,
    timeout: 180_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:4176',
    trace: 'off',
    video: 'off',
  },
  projects: releaseBrowserProjects(),
})
