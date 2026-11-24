import { test, expect } from '@playwright/test'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateClassicPcap } from '../pcap/fixtures/generate'
import { loadUniversalFiles } from './helpers/loadFiles.ts'
import { chooseMappingBundleFromLanding } from './helpers/mappingBundleFixture.ts'
import { CORRELATION_SESSION_LIMITS } from '../../src/domain/capabilityContract.ts'

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')

function ensureEightSources(): string[] {
  mkdirSync(fixturesDir, { recursive: true })
  const paths: string[] = []
  for (let i = 0; i < CORRELATION_SESSION_LIMITS.maxSources; i++) {
    const shared = i < 4 ? '10.0.0.5' : `10.0.${i}.9`
    const file = join(fixturesDir, `release-src-${i}.log`)
    writeFileSync(file, `source-${i} peer ${shared} connected\n`)
    paths.push(file)
  }
  return paths
}

function ensurePcap(): string {
  mkdirSync(fixturesDir, { recursive: true })
  const file = join(fixturesDir, 'lifecycle-release.pcap')
  writeFileSync(file, generateClassicPcap(12, 32))
  return file
}

test.describe('Release integration scenarios', () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' })
    await page.addInitScript(() => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify('light'))
      localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', JSON.stringify(true))
    })
  })

  test('eight-source staging accepts maxSources with shared and disjoint identities', async ({
    page,
  }) => {
    expect(CORRELATION_SESSION_LIMITS.maxSources).toBe(8)
    const files = ensureEightSources()
    await page.goto('/')
    await loadUniversalFiles(page, files)
    await expect(page.getByTestId('staging-confirm')).toBeVisible({ timeout: 30_000 })
    await expect(page.getByTestId('staging-source-list').locator('li')).toHaveCount(8)
    await expect(page.getByTestId('staging-confirm')).toBeEnabled()
  })

  test('dual-log search survives rapid query and case-sensitivity toggles', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('log-search')).toBeVisible()

    const orig = page.getByTestId('log-search-input')
    const anon = page.getByTestId('log-search-anon-input')

    // Rapid original-pane typing
    await orig.fill('1')
    await orig.fill('10')
    await orig.fill('10.0')
    await page.waitForTimeout(400)
    await expect(page.getByTestId('log-search-counter')).toBeVisible()

    // Case toggle should not clear the other pane's query
    await anon.fill('usr')
    await page.getByTestId('log-search-case-toggle').click()
    await page.getByTestId('log-search-case-toggle').click()
    await expect(anon).toHaveValue('usr')
    await expect(orig).toHaveValue('10.0')
  })

  test('cancel/reset then reimport without reload: text, pcap', async ({ page }) => {
    test.setTimeout(180_000)
    await page.goto('/')

    // Text
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await page.getByTestId('close-log').click()
    await expect(page.getByTestId('landing')).toBeVisible({ timeout: 15_000 })

    // PCAP
    await loadUniversalFiles(page, ensurePcap())
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 90_000 })
    await page.locator('.pcap-workspace__more > summary').click()
    await page.getByTestId('pcap-close').click()
    await expect(page.getByTestId('landing')).toBeVisible({ timeout: 15_000 })

    // Text again proves no sticky exclusive session
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
  })

  test('security surfaces keep a single primary export CTA', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
    await expect(page.getByTestId('export-download')).toBeVisible()
    await expect(page.getByTestId('export-bar').locator('.btn--primary')).toHaveCount(1)

    await page.getByTestId('close-log').click()
    await expect(page.getByTestId('landing')).toBeVisible()
    await loadUniversalFiles(page, ensurePcap())
    await expect(page.getByTestId('pcap-workspace')).toBeVisible({ timeout: 90_000 })
    await expect(page.getByTestId('pcap-export')).toBeVisible()
    await expect(page.getByTestId('pcap-workspace').locator('.btn--primary')).toHaveCount(1)
  })

  test('resolve-only entry and cancel returns to landing without reload', async ({ page }) => {
    await page.goto('/')
    // Choosing a bundle file goes straight to the lookup screen — no intermediate step.
    await chooseMappingBundleFromLanding(page)
    await expect(page.getByTestId('mapping-resolve-workspace')).toBeVisible({ timeout: 15_000 })
    await expect(page.getByTestId('resolve-return-lookup')).toBeVisible()
    await page.getByTestId('resolve-return-close').click()
    await expect(page.getByTestId('landing')).toBeVisible({ timeout: 15_000 })
    await page.getByTestId('try-sample').click()
    await expect(page.getByTestId('workspace')).toBeVisible({ timeout: 60_000 })
  })
})
