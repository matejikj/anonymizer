import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { loadUniversalFiles } from './helpers/loadFiles'
import { buildEthIpUdp, buildSipInviteWithSdp, envelope } from '../pcap/fixtures/voipCorpus'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import { classicHeader } from '../pcap/helpers/diagnosticPipeline'

function text(name: string) {
  return { name, mimeType: 'text/plain', buffer: Buffer.from(`peer 10.0.0.1 ${name}\n`) }
}
function pcap(name: string) {
  const packet = envelope(buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, buildSipInviteWithSdp()), 0)
  return { name, mimeType: 'application/octet-stream', buffer: Buffer.from(writeClassicPcap({ header: classicHeader(), packets: [packet] })) }
}

for (const kind of ['text', 'pcap'] as const) {
  test(`removing down to one ${kind} keeps the same primary analysis action`, async ({ page }) => {
    await page.setViewportSize({ width: kind === 'text' ? 390 : 1440, height: 1000 })
    await page.addInitScript(theme => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(theme))
      localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', 'true')
    }, kind === 'text' ? 'dark' : 'light')
    const file = kind === 'text' ? text : pcap
    const extension = kind === 'text' ? 'log' : 'pcap'
    await page.goto('/')
    await loadUniversalFiles(page, [file(`keep.${extension}`), file(`remove.${extension}`)])
    const staging = page.getByTestId('correlation-staging')
    await expect(staging).toBeVisible()
    const analyze = page.getByTestId('staging-confirm')
    await expect(analyze).toHaveText('Analyzovat soubory')
    await staging.getByRole('button', { name: `Odebrat soubor remove.${extension}`, exact: true }).click()
    await expect(staging.getByRole('listitem')).toHaveCount(1)
    await expect(analyze).toHaveText('Analyzovat soubor')
    await expect(analyze).toBeEnabled()
    await expect(page.getByTestId('staging-continue-single')).toHaveCount(0)
    await expect(page.getByTestId('staging-blocked-reason')).toHaveCount(0)
    await expect(staging).toContainText('Soubor můžete rovnou analyzovat')
    await expect.poll(() => staging.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true)
    const audit = await new AxeBuilder({ page }).include('[data-testid="correlation-staging"]')
      .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()
    expect(audit.violations.filter(v => v.impact === 'critical' || v.impact === 'serious')).toEqual([])
    await page.screenshot({ path: `/tmp/staging-single-${kind}.png` })
    await analyze.click()
    const outcome = page.getByTestId(kind === 'text' ? 'text-outcome-dialog' : 'pcap-outcome-dialog')
    await expect(outcome).toBeVisible({ timeout: 60_000 })
    await expect(staging).not.toBeVisible()
    await expect(page.getByTestId('correlation-workspace')).toHaveCount(0)
    await page.getByTestId(kind === 'text' ? 'text-outcome-dialog-close' : 'pcap-outcome-dialog-close').click()
    await expect(page.getByTestId(kind === 'text' ? 'workspace' : 'pcap-packet-grid-original')).toBeVisible()
  })
}

test('adding a second file restores plural analysis and processes the set', async ({ page }) => {
  await page.goto('/')
  await loadUniversalFiles(page, [text('a.log'), text('b.log')])
  const staging = page.getByTestId('correlation-staging')
  await expect(staging).toBeVisible()
  await staging.getByRole('button', { name: 'Odebrat soubor b.log', exact: true }).click()
  await expect(page.getByTestId('staging-confirm')).toHaveText('Analyzovat soubor')
  await staging.locator('input[type="file"]').setInputFiles(text('c.log'))
  await expect(staging.getByRole('listitem')).toHaveCount(2)
  await expect(page.getByTestId('staging-confirm')).toHaveText('Analyzovat soubory')
  await expect(page.getByTestId('staging-confirm')).toBeEnabled()
  await page.getByTestId('staging-confirm').click()
  await expect(page.getByTestId('correlation-workspace')).toBeVisible({ timeout: 60_000 })
})
