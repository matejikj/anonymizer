import { defineConfig } from '@playwright/test'
import { releaseBrowserProjects } from './playwright.browserProjects.ts'

/**
 * Accessibility release gate (axe + keyboard + forced-colors). Tri-browser by default.
 */
export default defineConfig({
  testDir: './tests/e2e',
  testMatch: [
    'a11y.spec.ts',
    'help-a11y.spec.ts',
    'landing-a11y-smoke.spec.ts',
    'keyboard-shell.spec.ts',
    'a11y-release-gate.spec.ts',
  ],
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  webServer: {
    command: 'npm run build && npm run preview -- --host 127.0.0.1 --port 4174',
    url: 'http://127.0.0.1:4174/',
    reuseExistingServer: false,
    timeout: 180_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:4174',
    trace: 'off',
    video: 'off',
  },
  projects: releaseBrowserProjects(),
})
