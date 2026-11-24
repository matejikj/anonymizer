/**
 * Step 3 acceptance — two independent selects in detection settings panel.
 * Text profile select and PCAP anonymization level select are separate.
 * In standalone text import/workspace the PCAP level is hidden.
 */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'
import { PCAP_ANONYMIZATION_LEVELS, DEFAULT_PCAP_LEVEL } from '../../src/pcap/profile/presets'
import { cs } from '../../src/i18n/cs'

const srcDir = join(dirname(fileURLToPath(import.meta.url)), '../../src')

describe('Step 3 — two independent selects', () => {
  it('PCAP level has exactly two options: diagnostic and high-privacy', () => {
    expect(PCAP_ANONYMIZATION_LEVELS).toEqual(['diagnostic', 'high-privacy'])
    expect(DEFAULT_PCAP_LEVEL).toBe('diagnostic')
  })

  it('i18n labels are distinct for text and PCAP selects', () => {
    expect(cs.header.unifiedProfileSection).toBeTruthy()
    expect(cs.header.pcapProfileSection).toBeTruthy()
    expect(cs.header.unifiedProfileSection).not.toBe(cs.header.pcapProfileSection)
    expect(cs.profiles.activeLabel).toBe('Profil detekce textových logů')
  })

  it('DetectionSettingsPopover mounts both selects and hides PCAP level in text workspace', () => {
    const src = readFileSync(join(srcDir, 'components/ui/DetectionSettingsPopover.tsx'), 'utf8')
    expect(src).toMatch(/TextProfileSelector/)
    expect(src).toMatch(/PcapAnonymizationLevelSelect/)
    expect(src).toMatch(/textOnlyChrome/)
    expect(src).toMatch(/phase === 'importing' \|\| phase === 'workspace'/)
  })

  it('PcapAnonymizationLevelSelect has aria-busy, aria-live, and keyboard-accessible select', () => {
    const src = readFileSync(join(srcDir, 'pcap/ui/PcapAnonymizationLevelSelect.tsx'), 'utf8')
    expect(src).toMatch(/aria-busy/)
    expect(src).toMatch(/aria-live="polite"/)
    expect(src).toMatch(/<select/)
    expect(src).toMatch(/aria-label/)
    expect(src).toMatch(/<label/)
    expect(src).toMatch(/pcapProfileSection/)
  })

  it('PcapEmptyDropzone has no preset cards — level is top-bar only', () => {
    const src = readFileSync(join(srcDir, 'pcap/ui/PcapEmptyDropzone.tsx'), 'utf8')
    expect(src).not.toMatch(/pcap-preset-card/)
    expect(src).not.toMatch(/applyLevel/)
    expect(src).not.toMatch(/setPcapAnonymizationLevel/)
  })

  it('PCAP level select options show recommended badge only on diagnostic', () => {
    expect(cs.pcap.presets.diagnosticName).toMatch(/doporučeno/)
    expect(cs.pcap.presets.highPrivacyName).not.toMatch(/doporučeno/)
  })
})
