import { describe, expect, it } from 'vitest'
import { SourceKind } from '../../src/domain/sourceArtifact'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema'
import { cloneRulesetConfig } from '../../src/domain/rulesetValidate'
import { createDefaultPcapProfile } from '../../src/pcap/profile/presets'
import {
  ProfileImpactKind,
  classifyProfileImpact,
  classifyPcapPayloadPolicyChange,
  profileImpactBlocksExport,
  compileCorrelationPolicy,
} from '../../src/correlation/profileCompatibility'

function textProfileWithFixedIp(value: string) {
  const config = cloneRulesetConfig(createDefaultRulesetConfig())
  config.profile.rules.push({
    id: 'ip-fixed',
    name: 'fixed ip',
    enabled: true,
    kind: 'literal',
    pattern: '10.',
    category: 'ip',
    replacement: { kind: 'fixed', value },
    priority: 5000,
  })
  return config
}

describe('Stage 26 profile impact classifier', () => {
  const basePolicy = compileCorrelationPolicy({
    sourceKinds: [SourceKind.Text, SourceKind.Pcap],
    textProfile: createDefaultRulesetConfig(),
    pcapProfile: createDefaultPcapProfile().profile,
  })

  it('classifies representation-policy when fixed IP replacement is introduced', () => {
    const after = compileCorrelationPolicy({
      sourceKinds: [SourceKind.Text, SourceKind.Pcap],
      textProfile: textProfileWithFixedIp('ip-1'),
      pcapProfile: createDefaultPcapProfile().profile,
    })
    const impact = classifyProfileImpact(basePolicy, after)
    expect(impact.kind).toBe(ProfileImpactKind.RepresentationPolicy)
    expect(profileImpactBlocksExport(impact)).toBe(true)
  })

  it('classifies discovery when custom rule pattern changes', () => {
    const afterConfig = cloneRulesetConfig(createDefaultRulesetConfig())
    afterConfig.profile.rules.push({
      id: 'extra',
      name: 'extra',
      enabled: true,
      kind: 'literal',
      pattern: 'secret-token',
      category: 'custom',
      replacement: { kind: 'generated' },
    })
    const after = compileCorrelationPolicy({
      sourceKinds: [SourceKind.Text, SourceKind.Pcap],
      textProfile: afterConfig,
      pcapProfile: createDefaultPcapProfile().profile,
    })
    const impact = classifyProfileImpact(basePolicy, after)
    expect(impact.kind).toBe(ProfileImpactKind.Discovery)
    expect(profileImpactBlocksExport(impact)).toBe(true)
  })

  it('never classifies representation change as coverage-only', () => {
    const after = compileCorrelationPolicy({
      sourceKinds: [SourceKind.Text, SourceKind.Pcap],
      textProfile: textProfileWithFixedIp('ip-2'),
      pcapProfile: createDefaultPcapProfile().profile,
    })
    const impact = classifyProfileImpact(basePolicy, after)
    expect(impact.kind).not.toBe(ProfileImpactKind.CoverageOnly)
  })

  it('classifies payload policy change as coverage-only', () => {
    const impact = classifyPcapPayloadPolicyChange('truncate-unsupported', 'preserve-all')
    expect(impact.kind).toBe(ProfileImpactKind.CoverageOnly)
    expect(profileImpactBlocksExport(impact)).toBe(false)
  })

  it('classifies identical policy as export-only', () => {
    const impact = classifyProfileImpact(basePolicy, basePolicy)
    expect(impact.kind).toBe(ProfileImpactKind.ExportOnly)
    expect(profileImpactBlocksExport(impact)).toBe(false)
  })
})
