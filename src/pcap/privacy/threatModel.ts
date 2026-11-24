/**
 * CF-15 — adversary models and per-level protection claims.
 *
 * Pseudonymization (stable aliases) is not irreversible anonymization.
 * Mapping bundles and communication-graph links remain sensitive assets.
 */

import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'

export type AdversaryModel =
  | 'casual-recipient'
  | 'inspection'
  | 'injection-known-plaintext'
  | 'cross-capture-correlation'

export type TransformationKind = 'anonymization' | 'pseudonymization' | 'diagnostic-preserve'

export type PrivacyRiskFlag =
  | 'exact-timestamp-deltas'
  | 'packet-lengths'
  | 'communication-graph'
  | 'service-ports'
  | 'tcp-ip-fingerprint'
  | 'sip-topology-capabilities'
  | 'preserved-unsafe-spans'
  | 'media-preserved-unsafe'

export interface AdversaryModelInfo {
  readonly id: AdversaryModel
  readonly summary: string
}

export const ADVERSARY_MODELS: readonly AdversaryModelInfo[] = [
  {
    id: 'casual-recipient',
    summary: 'Recipient without tooling who reads the export or shares it casually.',
  },
  {
    id: 'inspection',
    summary: 'Analyst with Wireshark/DNS/WHOIS who correlates pseudonyms to public topology.',
  },
  {
    id: 'injection-known-plaintext',
    summary: 'Party who injected known timing/size/content patterns into the original capture.',
  },
  {
    id: 'cross-capture-correlation',
    summary: 'Party who compares multiple exports or reuses a shared mapping bundle.',
  },
] as const

export type PcapPrivacyPreset = PcapAnonymizationLevel

export interface PresetThreatProfile {
  readonly preset: PcapPrivacyPreset
  readonly transformationKind: TransformationKind
  readonly protectsAgainst: readonly AdversaryModel[]
  readonly doesNotProtectAgainst: readonly AdversaryModel[]
  readonly intentionalResiduals: readonly PrivacyRiskFlag[]
  readonly notes: string
}

export const PRESET_THREAT_PROFILES: Record<PcapPrivacyPreset, PresetThreatProfile> = {
  diagnostic: {
    preset: 'diagnostic',
    transformationKind: 'pseudonymization',
    protectsAgainst: ['casual-recipient'],
    doesNotProtectAgainst: ['inspection', 'injection-known-plaintext', 'cross-capture-correlation'],
    intentionalResiduals: [
      'exact-timestamp-deltas',
      'packet-lengths',
      'communication-graph',
      'service-ports',
      'tcp-ip-fingerprint',
      'sip-topology-capabilities',
    ],
    notes:
      'Diagnostic is diagnostic sanitization / pseudonymization for troubleshooting — not irreversible anonymization. Timing, fingerprints, and topology metadata may remain.',
  },
  'high-privacy': {
    preset: 'high-privacy',
    transformationKind: 'pseudonymization',
    protectsAgainst: ['casual-recipient', 'injection-known-plaintext'],
    doesNotProtectAgainst: ['inspection', 'cross-capture-correlation'],
    intentionalResiduals: [
      'packet-lengths',
      'communication-graph',
      'service-ports',
      'sip-topology-capabilities',
    ],
    notes:
      'High-privacy is sanitization with stronger redaction: enumerated timing, normalized fingerprints, dropped media, truncated unsupported payloads. Packet sizes and stable alias graphs remain — not a claim that customer data is absent.',
  },
}

export function threatProfileForPreset(preset: string): PresetThreatProfile {
  if (preset === 'diagnostic' || preset === 'high-privacy') {
    return PRESET_THREAT_PROFILES[preset]
  }
  return PRESET_THREAT_PROFILES.diagnostic
}
