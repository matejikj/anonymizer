/**
 * Shared Playwright browser projects for product e2e and release gates.
 * Uses bundled macOS browsers when present; otherwise Playwright-installed binaries (CI).
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { devices, type Project } from '@playwright/test'

const root = path.dirname(fileURLToPath(import.meta.url))
const localBrowsersDir = path.join(root, '.playwright-browsers')
/** Prefer vendored browsers; only honor PLAYWRIGHT_BROWSERS_PATH when that tree exists. */
const browsersDir = (() => {
  const fromEnv = process.env.PLAYWRIGHT_BROWSERS_PATH
  if (fromEnv) {
    const resolved = path.isAbsolute(fromEnv) ? fromEnv : path.resolve(root, fromEnv)
    if (fs.existsSync(resolved)) return resolved
  }
  return localBrowsersDir
})()

function optionalExecutable(candidates: string[]): string | undefined {
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate
  }
  return undefined
}

export function releaseBrowserProjects(): Project[] {
  const firefoxExe = optionalExecutable([
    path.join(browsersDir, 'firefox-1538/firefox/Nightly.app/Contents/MacOS/firefox'),
    path.join(browsersDir, 'firefox-1490/firefox/firefox'),
    path.join(browsersDir, 'firefox-1490/firefox/Nightly.app/Contents/MacOS/firefox'),
  ])
  const webkitExe = optionalExecutable([
    path.join(browsersDir, 'webkit-2336/pw_run.sh'),
    path.join(browsersDir, 'webkit-2203/pw_run.sh'),
  ])

  const chromiumUse = {
    ...devices['Desktop Chrome'],
    ...(process.env.CI ? {} : { channel: 'chrome' as const }),
    launchOptions: {
      args: ['--disable-features=AutoDarkMode,AutoDarkModeOverWebContents'],
    },
  }

  const firefoxUse = {
    ...devices['Desktop Firefox'],
    launchOptions: {
      ...(firefoxExe ? { executablePath: firefoxExe } : {}),
      // macOS host agents often fail plugin-container sandbox_extension_issue (R10).
      firefoxUserPrefs: {
        'security.sandbox.content.level': 0,
        'security.sandbox.gpu.level': 0,
      },
    },
  }

  const webkitUse = {
    ...devices['Desktop Safari'],
    ...(webkitExe ? { launchOptions: { executablePath: webkitExe } } : {}),
  }

  return [
    { name: 'chromium', use: chromiumUse },
    { name: 'firefox', use: firefoxUse },
    { name: 'webkit', use: webkitUse },
  ]
}

export const RELEASE_RESULTS_DIR = path.join(root, 'tests/performance/results')
