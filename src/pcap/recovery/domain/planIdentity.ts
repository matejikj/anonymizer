/**
 * Bind recovery to the immutable PCAP plan identity (two levels only).
 * Maps plan.profileHash → policyHash; never introduces editable PCAP profiles or ruleset JSON.
 */

import {
  isPcapAnonymizationLevel,
  type PcapAnonymizationLevel,
} from '../../profile/pcapAnonymizationLevel'
import { PCAP_ENGINE_VERSION, type PcapPlanSnapshot } from '../../export/planSnapshot'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from './errors'
import type { PcapPlanIdentity, RecoveryExportOptions } from './types'
import { RECOVERY_EXPORT_DISABLED } from './types'

/** Minimal plan shape accepted by recovery — avoids depending on profile CRUD types. */
export interface PlanIdentitySource {
  readonly generationId: string
  readonly pcapLevel: PcapAnonymizationLevel
  /** Canonical built-in policy hash. */
  readonly policyHash?: string
  /** Plan wire historically named this profileHash; same bytes as policyHash. */
  readonly profileHash?: string
  readonly engineVersion: string
}

function policyHashOf(plan: PlanIdentitySource): string {
  return plan.policyHash || plan.profileHash || ''
}

export function planIdentityFromSnapshot(plan: PlanIdentitySource): PcapPlanIdentity {
  return {
    generationId: plan.generationId,
    pcapLevel: plan.pcapLevel,
    policyHash: policyHashOf(plan),
    engineVersion: plan.engineVersion || PCAP_ENGINE_VERSION,
  }
}

export function assertPlanIdentity(
  plan: PlanIdentitySource,
): PcapRecoveryResult<PcapPlanIdentity> {
  if (!plan.generationId || typeof plan.generationId !== 'string') {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'Plan generationId missing')
  }
  if (!isPcapAnonymizationLevel(plan.pcapLevel)) {
    return recoveryFail(
      PCAP_RECOVERY_ERROR.internal,
      'Plan pcapLevel must be diagnostic or high-privacy',
    )
  }
  if (!policyHashOf(plan)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'Plan policyHash missing')
  }
  if (!plan.engineVersion || typeof plan.engineVersion !== 'string') {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'Plan engineVersion missing')
  }
  return recoveryOk(planIdentityFromSnapshot(plan))
}

/** Recovery is supported for both runtime PCAP levels — same mechanism. */
export function isRecoverySupportedForLevel(level: PcapAnonymizationLevel): boolean {
  return isPcapAnonymizationLevel(level)
}

/**
 * Normalize export options. Default is disabled so the existing export hot path
 * stays unchanged until an explicit enable is supplied.
 */
export function normalizeRecoveryExportOptions(
  options: RecoveryExportOptions | undefined | null,
): RecoveryExportOptions {
  if (!options || options.enabled !== true) {
    return RECOVERY_EXPORT_DISABLED
  }
  return {
    enabled: true,
    ...(options.copyAnon === true ? { copyAnon: true } : {}),
  }
}

export function isRecoveryExportEnabled(
  options: RecoveryExportOptions | undefined | null,
): boolean {
  return normalizeRecoveryExportOptions(options).enabled
}

/** Guard used before starting recovery writing — both levels accepted. */
export function assertRecoveryExportAllowed(
  plan: Pick<PcapPlanSnapshot, 'pcapLevel'> | PcapPlanIdentity,
  options: RecoveryExportOptions | undefined | null,
): PcapRecoveryResult<RecoveryExportOptions> {
  const normalized = normalizeRecoveryExportOptions(options)
  if (!normalized.enabled) {
    return recoveryOk(RECOVERY_EXPORT_DISABLED)
  }
  if (!isRecoverySupportedForLevel(plan.pcapLevel)) {
    return recoveryFail(
      PCAP_RECOVERY_ERROR.internal,
      'Recovery requires diagnostic or high-privacy plan level',
    )
  }
  return recoveryOk(normalized)
}
