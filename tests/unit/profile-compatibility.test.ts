import { describe, expect, it } from 'vitest'
import { SourceKind } from '../../src/domain/sourceArtifact'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema'
import { cloneRulesetConfig } from '../../src/domain/rulesetValidate'
import { createDefaultPcapProfile } from '../../src/pcap/profile/presets'
import {
  PROFILE_COMPATIBILITY_OUTCOME,
  compileCorrelationPolicy,
  compileTextEffectivePolicy,
  compilePcapEffectivePolicy,
  evaluateProfileCompatibility,
  applyCategoryResolution,
  compatibilityAllowsProcessing,
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

describe('Stage 26 profile compatibility', () => {
  it('marks default text + default pcap as compatible', () => {
    const policy = compileCorrelationPolicy({
      sourceKinds: [SourceKind.Text, SourceKind.Pcap],
      textProfile: createDefaultRulesetConfig(),
      pcapProfile: createDefaultPcapProfile().profile,
    })
    const report = evaluateProfileCompatibility(policy)
    expect(report.outcome).toBe(PROFILE_COMPATIBILITY_OUTCOME.Compatible)
    expect(report.conflicts).toHaveLength(0)
    expect(compatibilityAllowsProcessing(report)).toBe(true)
  })

  it('detects blocking conflict for text fixed ip-1 token against wire-valid PCAP', () => {
    const policy = compileCorrelationPolicy({
      sourceKinds: [SourceKind.Text, SourceKind.Pcap],
      textProfile: textProfileWithFixedIp('ip-1'),
      pcapProfile: createDefaultPcapProfile().profile,
    })
    const report = evaluateProfileCompatibility(policy)
    expect(report.outcome).toBe(PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict)
    expect(report.conflicts.some((c) => c.category === 'ipv4')).toBe(true)
    expect(report.conflicts[0]?.reasonKey).toBe('text-fixed-non-wire-ipv4')
    expect(compatibilityAllowsProcessing(report)).toBe(false)
  })

  it('accepts wire-valid fixed IPv4 replacement as compatible with PCAP', () => {
    const policy = compileCorrelationPolicy({
      sourceKinds: [SourceKind.Text, SourceKind.Pcap],
      textProfile: textProfileWithFixedIp('9.9.9.9'),
      pcapProfile: createDefaultPcapProfile().profile,
    })
    const report = evaluateProfileCompatibility(policy)
    expect(report.outcome).toBe(PROFILE_COMPATIBILITY_OUTCOME.Compatible)
  })

  it('resolves conflict via session-override outcome', () => {
    const policy = compileCorrelationPolicy({
      sourceKinds: [SourceKind.Text, SourceKind.Pcap],
      textProfile: textProfileWithFixedIp('ip-1'),
      pcapProfile: createDefaultPcapProfile().profile,
    })
    const initial = evaluateProfileCompatibility(policy)
    const resolved = applyCategoryResolution(initial, 'ipv4', {
      kind: PROFILE_COMPATIBILITY_OUTCOME.SessionOverride,
    })
    expect(resolved.outcome).toBe(PROFILE_COMPATIBILITY_OUTCOME.SessionOverride)
    expect(resolved.unresolved).toHaveLength(0)
    expect(compatibilityAllowsProcessing(resolved)).toBe(true)
  })

  it('resolves conflict via uncorrelated-category outcome', () => {
    const policy = compileCorrelationPolicy({
      sourceKinds: [SourceKind.Text, SourceKind.Pcap],
      textProfile: textProfileWithFixedIp('ip-1'),
      pcapProfile: createDefaultPcapProfile().profile,
    })
    const initial = evaluateProfileCompatibility(policy)
    const resolved = applyCategoryResolution(initial, 'ipv4', {
      kind: PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory,
    })
    expect(resolved.outcome).toBe(PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory)
    expect(compatibilityAllowsProcessing(resolved)).toBe(true)
  })

  it('single-format sessions are always compatible', () => {
    const textOnly = evaluateProfileCompatibility(compileCorrelationPolicy({
      sourceKinds: [SourceKind.Text],
      textProfile: textProfileWithFixedIp('ip-1'),
    }))
    expect(textOnly.outcome).toBe(PROFILE_COMPATIBILITY_OUTCOME.Compatible)

    const pcapOnly = evaluateProfileCompatibility(compileCorrelationPolicy({
      sourceKinds: [SourceKind.Pcap],
      pcapProfile: createDefaultPcapProfile().profile,
    }))
    expect(pcapOnly.outcome).toBe(PROFILE_COMPATIBILITY_OUTCOME.Compatible)
  })

  it('produces stable policy hashes from canonical effective policy', () => {
    const config = createDefaultRulesetConfig()
    const a = compileTextEffectivePolicy(config)
    const b = compileTextEffectivePolicy(cloneRulesetConfig(config))
    expect(a.policyHash).toBe(b.policyHash)
    expect(a.representationHash).toBe(b.representationHash)
    expect(a.discoveryHash).toBe(b.discoveryHash)
  })

  it('compilePcapEffectivePolicy marks network categories wire-valid', () => {
    const pcap = compilePcapEffectivePolicy(createDefaultPcapProfile().profile)
    expect(pcap.categories.ipv4).toEqual({ kind: 'wire-valid' })
    expect(pcap.categories.mac).toEqual({ kind: 'wire-valid' })
  })
})
