/**
 * PCAP anonymization level — two built-in immutable policies only.
 * Not a user-editable profile; never serialized into text ruleset JSON.
 */

import type {
  MalformedPayloadPolicy,
  NetworkFingerprintPolicy,
  SanitizationPolicy,
  SipHandlingPolicy,
  UnsupportedPayloadPolicy,
  VoipMediaPolicy,
} from '../sanitize/types'
import {
  derivesDropMalformed,
  derivesTruncateUnsupported,
} from '../sanitize/types'
import {
  expectedTimestampsMode,
  sanitizationPolicyRealizesTable,
} from '../trust/policyTables'
import { ipModeForProfile } from '../anonymization/entityNamespaces'

export type PcapAnonymizationLevel = 'diagnostic' | 'high-privacy'

export const DEFAULT_PCAP_LEVEL: PcapAnonymizationLevel = 'diagnostic'

export const PCAP_ANONYMIZATION_LEVELS = ['diagnostic', 'high-privacy'] as const satisfies readonly PcapAnonymizationLevel[]

export function isPcapAnonymizationLevel(value: unknown): value is PcapAnonymizationLevel {
  return value === 'diagnostic' || value === 'high-privacy'
}

/** Address / timing mapping derived from a level (immutable). */
export interface PcapMapping {
  /**
   * Step 12 — bound to profile (not a third UI toggle):
   * diagnostic → topology-preserving; high-privacy → privacy-preserving.
   */
  readonly ip: 'topology-preserving' | 'privacy-preserving'
  readonly mac: 'locally-administered'
  readonly timestamps: 'relative' | 'relative-bucketed' | 'enumerated'
  readonly ephemeralPorts: 'preserve' | 'permute'
  /** T06 — non-catalog content-discovered signaling ports (e.g. SIP/5070). */
  readonly contentSignalingPorts: 'preserve' | 'permute'
  readonly vlan: 'map' | 'preserve'
  /** T16 — preserve MCC+MNC when IMSI carries explicit PLMN scope (diagnostic). */
  readonly imsiPlmn: 'preserve-plmn' | 'map-all'
}

export interface PcapProtocols {
  readonly dns: boolean
  readonly dhcp: boolean
  readonly sipSdp: boolean
  readonly tls: boolean
  readonly http: boolean
  readonly heuristicScan: boolean
  readonly dmr: boolean
  readonly mototrbo: boolean
  readonly vrrp: boolean
  readonly stp: boolean
  readonly cdp: boolean
  readonly lldp: boolean
  readonly lacp: boolean
  readonly eapol: boolean
}

const FINGERPRINT_NORMALIZE: NetworkFingerprintPolicy = {
  ttl: 'normalize',
  tcpWindow: 'normalize',
  flowLabel: 'normalize',
  ipv4Id: 'map',
  tcpSeq: 'map',
  // MSS/Window-Scale are a p0f-style OS/stack fingerprint; high-privacy's whole point is to
  // remove exactly this kind of residual, so normalize the values rather than preserve them.
  tcpOptions: 'normalize',
}

const FINGERPRINT_DIAGNOSTIC: NetworkFingerprintPolicy = {
  ttl: 'preserve-for-diagnostics',
  tcpWindow: 'preserve-for-diagnostics',
  flowLabel: 'map',
  ipv4Id: 'map',
  tcpSeq: 'map',
  tcpOptions: 'preserve-for-diagnostics',
}

const FAIL_CLOSED_SIP: SipHandlingPolicy = {
  incompleteMessage: 'truncate',
  malformed: 'drop',
  encrypted: 'mark-encrypted',
  reassemblyLimitExceeded: 'drop',
}

const DIAGNOSTIC_SIP: SipHandlingPolicy = {
  incompleteMessage: 'mask-in-place',
  malformed: 'mask-in-place',
  encrypted: 'mark-encrypted',
  reassemblyLimitExceeded: 'mask-in-place',
}

const PROTOCOLS_DIAGNOSTIC: PcapProtocols = {
  dns: true,
  dhcp: true,
  sipSdp: true,
  tls: true,
  http: true,
  heuristicScan: true,
  dmr: true,
  mototrbo: true,
  vrrp: true,
  stp: true,
  cdp: true,
  lldp: true,
  lacp: true,
  eapol: true,
}

const PROTOCOLS_HIGH_PRIVACY: PcapProtocols = {
  dns: true,
  dhcp: true,
  sipSdp: true,
  tls: true,
  http: true,
  heuristicScan: false,
  dmr: true,
  mototrbo: true,
  vrrp: true,
  stp: true,
  cdp: true,
  lldp: true,
  lacp: true,
  eapol: true,
}

const DIAGNOSTIC_MAPPING: PcapMapping = {
  ip: 'topology-preserving',
  mac: 'locally-administered',
  timestamps: 'relative',
  ephemeralPorts: 'permute',
  contentSignalingPorts: 'preserve',
  vlan: 'map',
  imsiPlmn: 'preserve-plmn',
}

const HIGH_PRIVACY_MAPPING: PcapMapping = {
  ip: 'privacy-preserving',
  mac: 'locally-administered',
  timestamps: 'enumerated',
  ephemeralPorts: 'permute',
  contentSignalingPorts: 'permute',
  vlan: 'map',
  imsiPlmn: 'map-all',
}

function buildPolicy(input: {
  level: PcapAnonymizationLevel
  unsupportedPayloadPolicy: UnsupportedPayloadPolicy
  malformedPayloadPolicy: MalformedPayloadPolicy
  mediaPolicy: VoipMediaPolicy
  preservePacketLengths: boolean
  preservePacketOrder: boolean
  protocols: PcapProtocols
  sipHandling: SipHandlingPolicy
  networkFingerprint: NetworkFingerprintPolicy
}): SanitizationPolicy {
  return {
    preset: input.level,
    unsupportedPayloadPolicy: input.unsupportedPayloadPolicy,
    malformedPayloadPolicy: input.malformedPayloadPolicy,
    truncateUnsupported: derivesTruncateUnsupported(input.unsupportedPayloadPolicy),
    dns: input.protocols.dns,
    dhcp: input.protocols.dhcp,
    sipSdp: input.protocols.sipSdp,
    tls: input.protocols.tls,
    http: input.protocols.http,
    heuristicScan: input.protocols.heuristicScan,
    dmr: input.protocols.dmr,
    mototrbo: input.protocols.mototrbo,
    vrrp: input.protocols.vrrp,
    stp: input.protocols.stp,
    cdp: input.protocols.cdp,
    lldp: input.protocols.lldp,
    lacp: input.protocols.lacp,
    eapol: input.protocols.eapol,
    dropMalformed: derivesDropMalformed(input.malformedPayloadPolicy),
    mediaPolicy: input.mediaPolicy,
    sipHandling: input.sipHandling,
    networkFingerprint: input.networkFingerprint,
    preservePacketLengths: input.preservePacketLengths,
    preservePacketOrder: input.preservePacketOrder,
  }
}

export const DIAGNOSTIC_POLICY: SanitizationPolicy = buildPolicy({
  level: 'diagnostic',
  unsupportedPayloadPolicy: 'mask-in-place',
  malformedPayloadPolicy: 'mask-application-in-place',
  mediaPolicy: 'strip-payload',
  preservePacketLengths: true,
  preservePacketOrder: true,
  protocols: PROTOCOLS_DIAGNOSTIC,
  sipHandling: DIAGNOSTIC_SIP,
  networkFingerprint: FINGERPRINT_DIAGNOSTIC,
})

export const HIGH_PRIVACY_POLICY: SanitizationPolicy = buildPolicy({
  level: 'high-privacy',
  unsupportedPayloadPolicy: 'truncate',
  malformedPayloadPolicy: 'drop',
  mediaPolicy: 'drop',
  preservePacketLengths: false,
  preservePacketOrder: true,
  protocols: PROTOCOLS_HIGH_PRIVACY,
  sipHandling: FAIL_CLOSED_SIP,
  networkFingerprint: FINGERPRINT_NORMALIZE,
})

// Step 11 — presets must realize the classification policy tables.
for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY] as const) {
  const check = sanitizationPolicyRealizesTable(policy)
  if (!check.ok) {
    throw new Error(
      `SanitizationPolicy for ${policy.preset} diverges from classification table: ${check.mismatches.join('; ')}`,
    )
  }
  const expectedTs = expectedTimestampsMode(policy.preset)
  const mappingTs = policy.preset === 'diagnostic' ? DIAGNOSTIC_MAPPING.timestamps : HIGH_PRIVACY_MAPPING.timestamps
  if (mappingTs !== expectedTs) {
    throw new Error(
      `Timestamp mapping for ${policy.preset} is ${mappingTs}, expected ${expectedTs} from TIMING policy`,
    )
  }
  const expectedIp = ipModeForProfile(policy.preset)
  const mappingIp = policy.preset === 'diagnostic' ? DIAGNOSTIC_MAPPING.ip : HIGH_PRIVACY_MAPPING.ip
  if (mappingIp !== expectedIp) {
    throw new Error(
      `IP mode for ${policy.preset} is ${mappingIp}, expected ${expectedIp} (bound to profile)`,
    )
  }
}

export interface PcapLevelDefinition {
  readonly level: PcapAnonymizationLevel
  readonly defaultName: string
  readonly mapping: PcapMapping
  readonly protocols: PcapProtocols
  readonly policy: SanitizationPolicy
}

const LEVEL_DEFINITIONS: Record<PcapAnonymizationLevel, PcapLevelDefinition> = {
  diagnostic: {
    level: 'diagnostic',
    defaultName: 'Diagnostické pro AI — doporučeno',
    mapping: DIAGNOSTIC_MAPPING,
    protocols: PROTOCOLS_DIAGNOSTIC,
    policy: DIAGNOSTIC_POLICY,
  },
  'high-privacy': {
    level: 'high-privacy',
    defaultName: 'Vysoké soukromí',
    mapping: HIGH_PRIVACY_MAPPING,
    protocols: PROTOCOLS_HIGH_PRIVACY,
    policy: HIGH_PRIVACY_POLICY,
  },
}

export function getLevelDefinition(level: PcapAnonymizationLevel): PcapLevelDefinition {
  return LEVEL_DEFINITIONS[level]
}

/** Sole factory of the two immutable runtime policies. */
export function presetToSanitizationPolicy(level: PcapAnonymizationLevel): SanitizationPolicy {
  return LEVEL_DEFINITIONS[level].policy
}

export function levelToMapping(level: PcapAnonymizationLevel): PcapMapping {
  return { ...LEVEL_DEFINITIONS[level].mapping }
}

/** Convert level mapping into SessionMapping / MappingAuthority config. */
export function levelToMappingConfig(level: PcapAnonymizationLevel): import('../anonymization/mapping').MappingConfig {
  const m = levelToMapping(level)
  return {
    ip: m.ip,
    mac: m.mac,
    timestamps: m.timestamps,
    ephemeralPorts: m.ephemeralPorts,
    contentSignalingPorts: m.contentSignalingPorts,
    vlan: m.vlan,
    imsiPlmn: m.imsiPlmn,
  }
}

export function levelDisplayName(level: PcapAnonymizationLevel): string {
  return LEVEL_DEFINITIONS[level].defaultName
}

/** Integrity hash of engine version + canonical built-in policy (no user profile id). */
export function hashPcapLevelPolicy(
  level: PcapAnonymizationLevel,
  engineVersion: string,
  /** T70 — free-text vocabulary content hash (feeds profileHash / report). */
  vocabularyHash = '',
): string {
  const def = LEVEL_DEFINITIONS[level]
  const material = JSON.stringify({
    engineVersion,
    level,
    mapping: def.mapping,
    protocols: def.protocols,
    policy: def.policy,
    vocabularyHash: vocabularyHash || undefined,
  })
  let h = 2166136261
  for (let i = 0; i < material.length; i++) {
    h ^= material.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return (h >>> 0).toString(16).padStart(8, '0')
}

/** @deprecated Alias — prefer presetToSanitizationPolicy(level). */
export function policyFromLevel(level: PcapAnonymizationLevel): SanitizationPolicy {
  return presetToSanitizationPolicy(level)
}
