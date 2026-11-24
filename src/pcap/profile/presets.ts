/**
 * Built-in PCAP anonymization policies (diagnostic | high-privacy).
 * Re-exports the two-level runtime model — no editable profiles.
 */

export {
  type PcapAnonymizationLevel,
  type PcapMapping,
  type PcapProtocols,
  type PcapLevelDefinition,
  DEFAULT_PCAP_LEVEL,
  PCAP_ANONYMIZATION_LEVELS,
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  isPcapAnonymizationLevel,
  getLevelDefinition,
  presetToSanitizationPolicy,
  levelToMapping,
  levelToMappingConfig,
  levelDisplayName,
  hashPcapLevelPolicy,
  policyFromLevel,
} from './pcapAnonymizationLevel'

/** @deprecated Use PcapAnonymizationLevel. */
export type BuiltinPcapPreset = import('./pcapAnonymizationLevel').PcapAnonymizationLevel

/** @deprecated Use PCAP_ANONYMIZATION_LEVELS. */
export const BUILTIN_PCAP_PRESETS = ['diagnostic', 'high-privacy'] as const

/** @deprecated Use DEFAULT_PCAP_LEVEL. */
export const DEFAULT_PCAP_PRESET = 'diagnostic' as const

import {
  DEFAULT_PCAP_LEVEL,
  getLevelDefinition,
  levelToMapping,
  presetToSanitizationPolicy,
  type PcapAnonymizationLevel,
  type PcapMapping,
} from './pcapAnonymizationLevel'
import type { SanitizationPolicy } from '../sanitize/types'

/** @deprecated Use getLevelDefinition. */
export function getPresetDefinition(level: PcapAnonymizationLevel) {
  const def = getLevelDefinition(level)
  return {
    preset: def.level,
    defaultId: `pcap-${def.level}`,
    defaultName: def.defaultName,
    unsupportedPayloadPolicy: def.policy.unsupportedPayloadPolicy,
    malformedPayloadPolicy: def.policy.malformedPayloadPolicy,
    mediaPolicy: def.policy.mediaPolicy,
    preservePacketLengths: def.policy.preservePacketLengths,
    preservePacketOrder: def.policy.preservePacketOrder,
    protocols: def.protocols,
    policy: def.policy,
  }
}

/** @deprecated Mapping is derived via levelToMapping. */
export const DEFAULT_PCAP_MAPPING: PcapMapping = levelToMapping('diagnostic')
/** @deprecated */
export const HIGH_PRIVACY_PCAP_MAPPING: PcapMapping = levelToMapping('high-privacy')

/**
 * Compatibility shim for call sites that still expect a profile-shaped object.
 * Not editable, not persisted, not importable — derived from level only.
 * @deprecated Prefer passing PcapAnonymizationLevel + presetToSanitizationPolicy.
 */
export interface DerivedPcapPolicyView {
  readonly id: string
  readonly name: string
  readonly preset: PcapAnonymizationLevel
  readonly unsupportedPayloadPolicy: SanitizationPolicy['unsupportedPayloadPolicy']
  readonly malformedPayloadPolicy: SanitizationPolicy['malformedPayloadPolicy']
  readonly mediaPolicy: SanitizationPolicy['mediaPolicy']
  readonly preservePacketLengths: boolean
  readonly preservePacketOrder: boolean
  readonly mapping: PcapMapping
  readonly protocols: ReturnType<typeof getLevelDefinition>['protocols']
}

/** @deprecated Use PcapAnonymizationLevel directly. */
export type PcapProfile = DerivedPcapPolicyView

export function derivedPolicyView(level: PcapAnonymizationLevel = DEFAULT_PCAP_LEVEL): DerivedPcapPolicyView {
  const def = getLevelDefinition(level)
  return {
    id: `pcap-${level}`,
    name: def.defaultName,
    preset: level,
    unsupportedPayloadPolicy: def.policy.unsupportedPayloadPolicy,
    malformedPayloadPolicy: def.policy.malformedPayloadPolicy,
    mediaPolicy: def.policy.mediaPolicy,
    preservePacketLengths: def.policy.preservePacketLengths,
    preservePacketOrder: def.policy.preservePacketOrder,
    mapping: levelToMapping(level),
    protocols: { ...def.protocols },
  }
}

/** @deprecated Use derivedPolicyView / presetToSanitizationPolicy. */
export function createPresetProfile(
  level: PcapAnonymizationLevel,
  options: { id?: string; name?: string; mapping?: PcapMapping } = {},
): DerivedPcapPolicyView {
  const view = derivedPolicyView(level)
  return {
    ...view,
    id: options.id ?? view.id,
    name: options.name ?? view.name,
    mapping: options.mapping ?? view.mapping,
  }
}

/** @deprecated Use derivedPolicyView(DEFAULT_PCAP_LEVEL). */
export function createDefaultPcapProfile(id = 'pcap-default'): { profile: DerivedPcapPolicyView } {
  return { profile: { ...derivedPolicyView(DEFAULT_PCAP_LEVEL), id } }
}

/** Convert a derived view (or legacy profile shape) to runtime policy. */
export function profileToSanitizationPolicy(
  profile: { readonly preset: PcapAnonymizationLevel } | PcapAnonymizationLevel,
): SanitizationPolicy {
  const level = typeof profile === 'string' ? profile : profile.preset
  return presetToSanitizationPolicy(level)
}
