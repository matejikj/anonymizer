import { defineConfig } from '@playwright/test'
import { releaseBrowserProjects } from './playwright.browserProjects.ts'

/**
 * Visual release gate (production preview build).
 * - Chromium: deterministic screenshot baselines (visual-baseline + visual-matrix)
 * - All browsers: Clear Glass hierarchy smoke (visual-hierarchy)
 */
export default defineConfig({
  testDir: './tests/e2e',
  testMatch: [
    'visual-baseline.spec.ts',
    'visual-matrix.spec.ts',
    'visual-hierarchy.spec.ts',
    'pcap-wireshark-visual.spec.ts',
  ],
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  webServer: {
    command: 'npm run build && npm run preview -- --host 127.0.0.1 --port 4175',
    url: 'http://127.0.0.1:4175/',
    reuseExistingServer: false,
    timeout: 180_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:4175',
    trace: 'off',
    video: 'off',
  },
  projects: releaseBrowserProjects(),
})
