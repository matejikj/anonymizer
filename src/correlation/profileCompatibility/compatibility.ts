/**
 * Profile compatibility evaluation for multi-source correlation (Stage 26).
 */

import type { CrossFormatCategory } from '../../mapping/crossFormat/types'
import {
  PROFILE_COMPATIBILITY_OUTCOME,
  type CorrelationEffectivePolicy,
  type PcapCategoryRepresentation,
  type ProfileCompatibilityConflict,
  type ProfileCompatibilityOutcome,
  type ProfileCompatibilityReport,
  type ProfileConflictResolution,
  type TextCategoryRepresentation,
} from './types'

const SHARED_CATEGORIES: readonly CrossFormatCategory[] = [
  'ipv4', 'ipv6', 'mac', 'hostname', 'port', 'phone', 'email', 'user',
]

function textActive(rep: TextCategoryRepresentation | null): boolean {
  return rep != null && rep.kind !== 'disabled'
}

function pcapActive(rep: PcapCategoryRepresentation | null): boolean {
  return rep != null && rep.kind !== 'disabled'
}

function isCompatiblePair(
  cf: CrossFormatCategory,
  text: TextCategoryRepresentation | null,
  pcap: PcapCategoryRepresentation | null,
): boolean {
  if (!textActive(text) || !pcapActive(pcap)) return true
  if (!text || !pcap) return true

  if (text.kind === 'generated' && text.wireCompatible && pcap.kind === 'wire-valid') {
    return true
  }
  if (text.kind === 'fixed' && text.wireCompatible && pcap.kind === 'wire-valid') {
    return true
  }
  if (cf === 'port' && text.kind === 'generated' && pcap.kind === 'preserved') {
    return true
  }
  if (cf === 'hostname' && text.kind === 'generated' && pcap.kind === 'wire-valid') {
    return true
  }
  return false
}

function buildConflict(
  category: CrossFormatCategory,
  text: TextCategoryRepresentation | null,
  pcap: PcapCategoryRepresentation | null,
): ProfileCompatibilityConflict {
  const resolutions: ProfileConflictResolution[] = [
    { kind: PROFILE_COMPATIBILITY_OUTCOME.SessionOverride },
    { kind: PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory },
    { kind: PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict },
  ]
  return {
    category,
    reasonKey: conflictReasonKey(category, text, pcap),
    textRepresentation: text,
    pcapRepresentation: pcap,
    resolutions,
    recommended: { kind: PROFILE_COMPATIBILITY_OUTCOME.SessionOverride },
  }
}

function conflictReasonKey(
  category: CrossFormatCategory,
  text: TextCategoryRepresentation | null,
  pcap: PcapCategoryRepresentation | null,
): string {
  if (text?.kind === 'fixed' && !text.wireCompatible) {
    return `text-fixed-non-wire-${category}`
  }
  if (text?.kind === 'generated' && !text.wireCompatible) {
    return `text-generated-non-wire-${category}`
  }
  if (text?.kind === 'disabled' && pcapActive(pcap)) {
    return `text-disabled-pcap-active-${category}`
  }
  void pcap
  return `representation-mismatch-${category}`
}

export function evaluateProfileCompatibility(
  policy: CorrelationEffectivePolicy,
): ProfileCompatibilityReport {
  if (!policy.text || !policy.pcap) {
    return {
      outcome: PROFILE_COMPATIBILITY_OUTCOME.Compatible,
      policy,
      conflicts: [],
      unresolved: [],
    }
  }

  const conflicts: ProfileCompatibilityConflict[] = []

  for (const cf of SHARED_CATEGORIES) {
    const textRep = policy.text.categories[cf]
    const pcapRep = policy.pcap.categories[cf]
    if (!textActive(textRep) || !pcapActive(pcapRep)) continue
    if (textRep?.kind === 'generated' && !textRep.wireCompatible) continue
    if (textRep?.kind === 'disabled') continue
    if (!isCompatiblePair(cf, textRep, pcapRep)) {
      conflicts.push(buildConflict(cf, textRep, pcapRep))
    }
  }

  if (conflicts.length === 0) {
    return {
      outcome: PROFILE_COMPATIBILITY_OUTCOME.Compatible,
      policy,
      conflicts: [],
      unresolved: [],
    }
  }

  return {
    outcome: PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict,
    policy,
    conflicts: Object.freeze(conflicts),
    unresolved: Object.freeze([...conflicts]),
  }
}

export function applyCategoryResolution(
  report: ProfileCompatibilityReport,
  category: CrossFormatCategory,
  resolution: ProfileConflictResolution,
): ProfileCompatibilityReport {
  const conflict = report.conflicts.find((c) => c.category === category)
  if (!conflict) return report
  if (!conflict.resolutions.some((r) => r.kind === resolution.kind)) return report

  const remaining = report.unresolved.filter((c) => c.category !== category)
  let outcome: ProfileCompatibilityOutcome = report.outcome

  if (remaining.length > 0) {
    outcome = PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict
  } else if (resolution.kind === PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict) {
    outcome = PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict
  } else {
    outcome = resolution.kind
  }

  return {
    ...report,
    outcome,
    unresolved: Object.freeze(remaining),
  }
}

export function compatibilityAllowsProcessing(report: ProfileCompatibilityReport): boolean {
  if (report.unresolved.length > 0) return false
  return report.outcome !== PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict
}

export function deriveSessionOutcome(
  resolutions: ReadonlyMap<CrossFormatCategory, ProfileConflictResolution>,
): ProfileCompatibilityOutcome {
  if (resolutions.size === 0) return PROFILE_COMPATIBILITY_OUTCOME.Compatible
  const kinds = [...resolutions.values()].map((r) => r.kind)
  if (kinds.some((k) => k === PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict)) {
    return PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict
  }
  if (kinds.every((k) => k === PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory)) {
    return PROFILE_COMPATIBILITY_OUTCOME.UncorrelatedCategory
  }
  return PROFILE_COMPATIBILITY_OUTCOME.SessionOverride
}
