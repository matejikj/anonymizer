/**
 * Enterprise step 11 — classification → policy action tables.
 * One sanitization engine; two immutable tables (diagnostic | high-privacy).
 * Not a third profile; not a gate value.
 */

import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'
import type { SanitizationPolicy } from '../sanitize/types'
import type {
  FieldClassification,
  PolicyAction,
  SensitiveField,
} from './classification'
import { FIELD_CLASSIFICATIONS } from './classification'

/** Context that can refine HIGH_PRIVACY UNKNOWN_UNVERIFIED (MASK vs DROP). */
export interface PolicyApplyContext {
  /**
   * Transport carrying the field.
   * High-privacy TCP stream data prefers MASK (avoid fake single-segment loss).
   */
  readonly transport?: 'tcp' | 'udp' | 'sctp' | 'other'
  /**
   * Independent datagram / known media record (RTP/RTCP/…): DROP allowed under HP.
   */
  readonly independentDatagram?: boolean
}

export type ClassificationPolicyTable = Readonly<Record<FieldClassification, PolicyAction>>

/**
 * Diagnostic for AI — structure/count/order/length/Δt preserved;
 * secrets and unverified plaintext never leave as originals; DROP packet forbidden.
 */
export const DIAGNOSTIC_CLASSIFICATION_POLICY: ClassificationPolicyTable = {
  IDENTITY: 'MAP',
  SECRET: 'MASK',
  MEDIA: 'MASK',
  UNKNOWN_UNVERIFIED: 'MASK',
  FINGERPRINT: 'KEEP',
  TIMING: 'RELATIVE',
  ENCRYPTED_OPAQUE: 'PRESERVE',
  SAFE_METADATA: 'KEEP',
}

/**
 * High privacy — same engine; aggressive MEDIA DROP and fingerprint/timing harden.
 * UNKNOWN_UNVERIFIED defaults to MASK; DROP only for independent datagrams (see apply).
 */
export const HIGH_PRIVACY_CLASSIFICATION_POLICY: ClassificationPolicyTable = {
  IDENTITY: 'MAP',
  SECRET: 'MASK',
  MEDIA: 'DROP',
  UNKNOWN_UNVERIFIED: 'MASK',
  FINGERPRINT: 'NORMALIZE',
  TIMING: 'ENUMERATE',
  ENCRYPTED_OPAQUE: 'PRESERVE',
  SAFE_METADATA: 'KEEP',
}

export function classificationPolicyTable(
  profile: PcapAnonymizationLevel,
): ClassificationPolicyTable {
  return profile === 'high-privacy'
    ? HIGH_PRIVACY_CLASSIFICATION_POLICY
    : DIAGNOSTIC_CLASSIFICATION_POLICY
}

/**
 * Resolve the policy action for one classification under a profile.
 * High-privacy UNKNOWN_UNVERIFIED may DROP only for independent datagrams (not TCP streams).
 */
export function actionForClassification(
  profile: PcapAnonymizationLevel,
  classification: FieldClassification,
  ctx: PolicyApplyContext = {},
): PolicyAction {
  const base = classificationPolicyTable(profile)[classification]

  if (
    profile === 'high-privacy'
    && classification === 'UNKNOWN_UNVERIFIED'
  ) {
    if (ctx.transport === 'tcp') return 'MASK'
    if (ctx.independentDatagram === true) return 'DROP'
    // UDP/other unverified: MASK preferred (safe default); DROP only when explicitly datagram.
    return 'MASK'
  }

  return base
}

export interface PolicyAppliedField extends SensitiveField {
  readonly action: PolicyAction
  readonly profile: PcapAnonymizationLevel
}

/**
 * classify → applyPolicy(profile): attach actions to parser-emitted fields.
 * Same SensitiveField[] + two profiles → different action sets (acceptance).
 */
export function applyPolicy(
  profile: PcapAnonymizationLevel,
  fields: readonly SensitiveField[],
  ctx: PolicyApplyContext = {},
): readonly PolicyAppliedField[] {
  return fields.map((field) => ({
    ...field,
    profile,
    action: actionForClassification(profile, field.classification, ctx),
  }))
}

/** Diagnostic forbids whole-packet DROP for sanitization completeness. */
export function forbidsPacketDrop(profile: PcapAnonymizationLevel): boolean {
  return profile === 'diagnostic'
}

/** Pipeline stages — one engine, profile only switches the policy table. */
export const SANITIZATION_PIPELINE_STAGES = [
  'parse',
  'reassembly',
  'classify',
  'applyPolicy',
  'rewrite',
  'checksums',
  'verify',
] as const

export type SanitizationPipelineStage = (typeof SANITIZATION_PIPELINE_STAGES)[number]

/**
 * Runtime SanitizationPolicy must realize the classification table.
 * Used by tests and as a guard when presets change.
 */
export function sanitizationPolicyRealizesTable(
  policy: SanitizationPolicy,
): { readonly ok: boolean; readonly mismatches: readonly string[] } {
  const profile = policy.preset
  const table = classificationPolicyTable(profile)
  const mismatches: string[] = []

  // MEDIA
  if (table.MEDIA === 'MASK' && policy.mediaPolicy === 'drop') {
    mismatches.push('MEDIA:MASK requires mediaPolicy≠drop')
  }
  if (table.MEDIA === 'DROP' && policy.mediaPolicy !== 'drop') {
    mismatches.push('MEDIA:DROP requires mediaPolicy=drop')
  }

  // UNKNOWN_UNVERIFIED — diagnostic never DROP packets via truncate/drop of whole unsupported
  if (profile === 'diagnostic') {
    if (policy.unsupportedPayloadPolicy !== 'mask-in-place') {
      mismatches.push('diagnostic UNKNOWN requires unsupportedPayloadPolicy=mask-in-place')
    }
    if (!policy.preservePacketLengths || !policy.preservePacketOrder) {
      mismatches.push('diagnostic requires preservePacketLengths+Order')
    }
    if (policy.mediaPolicy === 'drop') {
      mismatches.push('diagnostic forbids mediaPolicy=drop')
    }
  }

  // FINGERPRINT
  if (table.FINGERPRINT === 'KEEP') {
    const fp = policy.networkFingerprint
    if (fp.ttl === 'normalize' || fp.tcpWindow === 'normalize' || fp.tcpOptions === 'normalize') {
      mismatches.push('FINGERPRINT:KEEP should not normalize ttl/window/options')
    }
  }
  if (table.FINGERPRINT === 'NORMALIZE') {
    const fp = policy.networkFingerprint
    if (fp.ttl !== 'normalize' || fp.tcpWindow !== 'normalize' || fp.tcpOptions !== 'normalize') {
      mismatches.push('FINGERPRINT:NORMALIZE requires ttl/window/options normalize')
    }
  }

  // TIMING is on mapping (timestamps), not SanitizationPolicy — checked separately via levelToMapping.

  // SECRET / ENCRYPTED always MASK / PRESERVE — both profiles share fail-closed secrets path;
  // no contradictory media/unsupported setting encodes that here beyond table presence.
  for (const c of FIELD_CLASSIFICATIONS) {
    if (table[c] === undefined) mismatches.push(`missing table entry: ${c}`)
  }

  return { ok: mismatches.length === 0, mismatches }
}

export function timingActionForProfile(profile: PcapAnonymizationLevel): PolicyAction {
  return classificationPolicyTable(profile).TIMING
}

export function expectedTimestampsMode(
  profile: PcapAnonymizationLevel,
): 'relative' | 'enumerated' {
  return timingActionForProfile(profile) === 'ENUMERATE' ? 'enumerated' : 'relative'
}
