import { describe, expect, it } from 'vitest'
import {
  DEFAULT_PCAP_LEVEL,
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  PCAP_ANONYMIZATION_LEVELS,
  presetToSanitizationPolicy,
} from '../../src/pcap/profile/presets.ts'
import {
  getActivePcapLevel,
  setActivePcapLevel,
} from '../../src/pcap/profile/activePcapProfile.ts'

describe('PCAP level policy consistency (step 2)', () => {
  it('active level and presetToSanitizationPolicy stay aligned', () => {
    setActivePcapLevel('high-privacy')
    expect(getActivePcapLevel()).toBe('high-privacy')
    expect(presetToSanitizationPolicy(getActivePcapLevel())).toEqual(HIGH_PRIVACY_POLICY)

    setActivePcapLevel('diagnostic')
    expect(presetToSanitizationPolicy(getActivePcapLevel())).toEqual(DIAGNOSTIC_POLICY)
  })

  it('exposes exactly two built-in levels', () => {
    expect(PCAP_ANONYMIZATION_LEVELS).toEqual(['diagnostic', 'high-privacy'])
    expect(DEFAULT_PCAP_LEVEL).toBe('diagnostic')
  })
})
