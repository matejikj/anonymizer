import { test, expect } from '@playwright/test'
import { readFileSync, mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { REFERENCE_VIEWPORT } from '../../src/styles/referenceCompositions.ts'
import { loadUniversalFiles } from './helpers/loadFiles.ts'
import { chooseMappingBundleFromLanding } from './helpers/mappingBundleFixture.ts'
import { generateClassicPcap } from '../pcap/fixtures/generate'

const root = dirname(fileURLToPath(import.meta.url))
const fixturesDir = join(root, 'fixtures')

const VIEWPORTS = [
  { name: '1280x800', size: { width: 1280, height: 800 } },
  { name: '1024x768', size: { width: 1024, height: 768 } },
  { name: 'narrow', size: { width: 900, height: 700 } },
] as const

async function prepare(
  page: import('@playwright/test').Page,
  theme: 'light' | 'dark',
  viewport = REFERENCE_VIEWPORT,
) {
  await page.setViewportSize(viewport)
  await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' })
  await page.addInitScript((t) => {
    localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(t))
    localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
  }, theme)
}

function smallPcapBytes(): Buffer {
  try {
    return readFileSync(join(root, '../pcap/fixtures/generated/small-100.pcap'))
  } catch {
    return generateClassicPcap(20, 32)
  }
}

function ensureMultisourceFixtures(): { a: string; b: string } {
  mkdirSync(fixturesDir, { recursive: true })
  const a = join(fixturesDir, 'multisource-a.log')
  const b = join(fixturesDir, 'multisource-b.log')
  if (!existsSync(a)) writeFileSync(a, 'peer 10.0.0.5 connected\n')
  if (!existsSync(b)) writeFileSync(b, 'server 10.0.0.5 ready\n')
  return { a, b }
}

function ensurePcapFixture(): string {
  mkdirSync(fixturesDir, { recursive: true })
  const file = join(fixturesDir, 'visual-matrix.pcap')
  if (!existsSync(file)) {
    writeFileSync(file, smallPcapBytes())
  }
  return file
}

test.describe('Clear Glass Operations visual matrix', () => {
  test.beforeEach(({ browserName }) => {
    test.skip(browserName !== 'chromium', 'Screenshot baselines are chromium; a11y covers tri-browser')
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`landing ${theme} @ 1440×1000`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      await expect(page.getByTestId('landing')).toBeVisible()
      await expect(page.getByTestId('app-header')).toBeVisible()
      await expect(page.getByTestId('first-visit-tour')).toHaveCount(0)
      await expect(page.locator('.app-shell')).toHaveAttribute('data-design', 'clear-glass-operations')
      await expect(page).toHaveScreenshot(`visual-matrix-landing-${theme}.png`, { animations: 'disabled' })
    })

    test(`paste open ${theme} @ 1440×1000`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      await page.getByTestId('paste-toggle').click()
      await expect(page.getByTestId('landing-paste')).toBeVisible()
      await expect(page).toHaveScreenshot(`visual-matrix-paste-open-${theme}.png`, { animations: 'disabled' })
    })

    test(`onboarding ${theme} @ 1440×1000`, async ({ page }) => {
      await page.setViewportSize(REFERENCE_VIEWPORT)
      await page.emulateMedia({ colorScheme: theme, reducedMotion: 'reduce' })
      await page.addInitScript((t) => {
        localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(t))
        localStorage.removeItem('rnd-log-anonymizer:pref:onboardingComplete')
      }, theme)
      await page.goto('/')
      await expect(page.getByTestId('first-visit-tour')).toBeVisible({ timeout: 10_000 })
      await expect(page).toHaveScreenshot(`visual-matrix-onboarding-${theme}.png`, { animations: 'disabled' })
    })

    test(`text workspace ${theme} @ 1440×1000`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      await page.getByTestId('try-sample').click()
      await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
      await expect(page.getByTestId('dual-log')).toBeVisible()
      await expect(page).toHaveScreenshot(`visual-matrix-text-workspace-${theme}.png`, { animations: 'disabled' })
    })

    test(`help panel ${theme} @ 1440×1000`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      await page.getByTestId('help-open').click()
      await expect(page.getByTestId('help-panel')).toBeVisible()
      await expect(page).toHaveScreenshot(`visual-matrix-help-${theme}.png`, { animations: 'disabled' })
    })

    test(`resolve-only ${theme} @ 1440×1000`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      // Choosing a file goes straight to the lookup/browse screen — no intermediate
      // "pick a bundle" step to click through.
      await chooseMappingBundleFromLanding(page)
      await expect(page.getByTestId('resolve-return-lookup')).toBeVisible({
        timeout: 15_000,
      })
      await expect(page).toHaveScreenshot(`visual-matrix-resolve-only-${theme}.png`, { animations: 'disabled' })
    })

    test(`pcap workspace ${theme} @ 1440×1000`, async ({ page }) => {
      await prepare(page, theme)
      await page.goto('/')
      await loadUniversalFiles(page, ensurePcapFixture())
      await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 90_000 })
      await expect(page.getByTestId('pcap-export')).toBeVisible()
      await expect(page).toHaveScreenshot(`visual-matrix-pcap-workspace-${theme}.png`, { animations: 'disabled' })
    })
  }

  // Viewport matrix — landing light only (budget); dark covered above at reference size
  for (const vp of VIEWPORTS) {
    test(`landing light @ ${vp.name}`, async ({ page }) => {
      await prepare(page, 'light', vp.size)
      await page.goto('/')
      await expect(page.getByTestId('landing')).toBeVisible()
      await expect(page).toHaveScreenshot(`visual-matrix-landing-light-${vp.name}.png`, { animations: 'disabled' })
    })
  }

  test('landing light @ 200% zoom', async ({ page }) => {
    await prepare(page, 'light')
    await page.goto('/')
    await page.evaluate(() => {
      document.documentElement.style.zoom = '2'
    })
    await expect(page.getByTestId('landing')).toBeVisible()
    await expect(page).toHaveScreenshot('visual-matrix-landing-light-zoom200.png', { animations: 'disabled' })
  })

  test('text workspace rules panel light', async ({ page }) => {
    await prepare(page, 'light')
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    const rulesTab = page.getByTestId('review-tab-rules')
    if (await rulesTab.count()) {
      await rulesTab.click()
      await expect(page.getByTestId('review-rules')).toBeVisible()
    }
    await expect(page).toHaveScreenshot('visual-matrix-text-rules-light.png', { animations: 'disabled' })
  })

  test('correlation staging light @ 1440×1000', async ({ page }) => {
    await prepare(page, 'light')
    await page.goto('/')
    const { a, b } = ensureMultisourceFixtures()
    await loadUniversalFiles(page, [a, b])
    await expect(page.getByTestId('staging-confirm')).toBeVisible({ timeout: 30_000 })
    await expect(page).toHaveScreenshot('visual-matrix-correlation-staging-light.png', { animations: 'disabled' })
  })
})
