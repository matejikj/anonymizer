import { defineConfig } from '@playwright/test'
import { releaseBrowserProjects } from './playwright.browserProjects.ts'

/**
 * Design-system gallery — Vite serve (not production dist).
 */
export default defineConfig({
  testDir: './tests/e2e',
  testMatch: ['design-system-gallery.spec.ts'],
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list']],
  webServer: {
    command: 'npx vite --host 127.0.0.1 --port 5174',
    url: 'http://127.0.0.1:5174/gallery.html',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  use: {
    baseURL: 'http://127.0.0.1:5174',
    trace: 'off',
    video: 'off',
  },
  projects: releaseBrowserProjects(),
})
