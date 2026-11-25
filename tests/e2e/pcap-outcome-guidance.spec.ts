import { test, expect } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'
import { buildEthIpUdp, buildSipInviteWithSdp, envelope } from '../pcap/fixtures/voipCorpus'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import { classicHeader } from '../pcap/helpers/diagnosticPipeline'
import { loadUniversalFiles } from './helpers/loadFiles'
import { selectPcapLevel } from './helpers/selectPcapLevel'

for (const scenario of [
  { theme: 'light', width: 1440, dmr: false },
  { theme: 'dark', width: 390, dmr: false },
  { theme: 'light', width: 1440, dmr: true },
  { theme: 'dark', width: 390, dmr: true },
] as const) {
  test(`protocol guidance: ${scenario.theme} ${scenario.width}px, exposed voice=${scenario.dmr}`, async ({ page }) => {
    await page.setViewportSize({ width: scenario.width, height: 1000 })
    await page.addInitScript(theme => {
      localStorage.setItem('rnd-log-anonymizer:pref:theme', JSON.stringify(theme))
      localStorage.setItem('rnd-log-anonymizer:pref:onboardingComplete', 'true')
    }, scenario.theme)
    const packets = [envelope(buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, buildSipInviteWithSdp()), 0)]
    if (scenario.dmr) {
      const dmr = new Uint8Array(53)
      dmr.set(new TextEncoder().encode('DMRD'))
      dmr.set([0, 4, 1], 5)
      dmr.set([0, 4, 2], 8)
      packets.push(envelope(buildEthIpUdp([10, 0, 0, 3], [10, 0, 0, 4], 62031, 62031, dmr), 1))
    }
    await page.goto('/')
    await selectPcapLevel(page, 'diagnostic')
    await loadUniversalFiles(page, { name: 'protocol-guidance.pcap', mimeType: 'application/octet-stream',
      buffer: Buffer.from(writeClassicPcap({ header: classicHeader(), packets })) })
    const panel = page.getByTestId('pcap-workspace-outcome')
    await expect(panel).toBeVisible({ timeout: 60_000 })
    await expect(panel).toHaveAttribute('data-gate', scenario.dmr ? 'AI_READY_WITH_GAPS' : 'AI_READY')
    await expect(page.getByTestId('pcap-workspace-outcome-protocol-sip-sip')).toContainText('Call-ID')
    await expect(page.getByTestId('pcap-workspace-outcome-protocol-sdp-sdp')).toContainText('ICE')
    await expect(page.getByTestId('pcap-workspace-outcome-protocol-network-headers-udp')).toContainText('sama nechrání')
    await expect(page.getByTestId('pcap-workspace-outcome-protocol-network-headers-tcp')).toHaveCount(0)
    await expect(page.getByTestId('pcap-workspace-outcome-assurance')).toContainText('Pro diagnostiku zůstávají')
    await expect(panel).not.toContainText(/ověřte|zkontrolujte|k prověření|Před předáním AI je potřeba kontrola|NOT AI READY/i)
    const decision = panel.locator('.anonymization-outcome__decision')
    expect(await decision.evaluate(el => getComputedStyle(el).getPropertyValue('--outcome-tone').trim()))
      .toBe(await decision.evaluate(el => getComputedStyle(el).getPropertyValue('--color-ok').trim()))
    if (scenario.dmr) {
      await expect(panel.getByRole('heading', { name: 'Anonymizováno — část obsahu skryta (AI ji neuvidí)' })).toBeVisible()
      await expect(page.getByTestId('pcap-workspace-outcome-protocol-dmr-dmr')).toContainText('AMBE hlas')
      await expect(page.getByTestId('pcap-workspace-outcome-family-dmr')).toHaveAttribute('data-family-state', 'anonymized-with-loss')
    }
    const dialog = page.getByTestId('pcap-outcome-dialog')
    await expect(dialog.getByRole('heading', { name: 'Výsledek anonymizace', exact: true })).toBeFocused()
    await expect.poll(() => page.getByTestId('pcap-outcome-dialog-close').evaluate(el => {
      const button = el.getBoundingClientRect()
      return button.top >= 0 && button.bottom <= window.innerHeight
    })).toBe(true)
    await expect.poll(() => dialog.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true)
    const audit = await new AxeBuilder({ page }).include('[data-testid="pcap-outcome-dialog"]')
      .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()
    expect(audit.violations.filter(v => v.impact === 'critical' || v.impact === 'serious')).toEqual([])
    await page.screenshot({ path: `/tmp/pcap-feedback-${scenario.theme}-${scenario.width}-${scenario.dmr ? 'review' : 'ready'}.png` })
    await page.getByTestId('pcap-outcome-dialog-close').click()
    await expect(dialog).not.toBeVisible()
  })
}
