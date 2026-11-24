import { describe, expect, it } from 'vitest'
import { validateMappingConfig } from '../../src/mapping/protocol'
import { levelToMapping } from '../../src/pcap/profile/pcapAnonymizationLevel'

describe('validateMappingConfig — T16 imsiPlmn', () => {
  it('accepts diagnostic and high-privacy level mappings (7 keys)', () => {
    expect(validateMappingConfig(levelToMapping('diagnostic'))).toBeNull()
    expect(validateMappingConfig(levelToMapping('high-privacy'))).toBeNull()
  })

  it('rejects legacy 6-key configs missing imsiPlmn', () => {
    const legacy = {
      ip: 'topology-preserving',
      mac: 'locally-administered',
      timestamps: 'relative',
      ephemeralPorts: 'preserve',
      contentSignalingPorts: 'preserve',
      vlan: 'map',
    }
    expect(validateMappingConfig(legacy)?.message).toBe('invalid mapping config')
  })
})
