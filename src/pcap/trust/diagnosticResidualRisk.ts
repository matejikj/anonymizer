/**
 * Enterprise step 5 — intentional residual risk axes for diagnostic exports.
 * Must stay visible in UI even when gate === AI_READY.
 */

import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel'
import type { PcapPrivacyReport } from '../privacy/privacyReport'
import type { PrivacyRiskFlag } from '../privacy/threatModel'

export interface DiagnosticResidualRisk {
  /** Pseudonymized communication graph remains correlatable. */
  readonly graph: boolean
  /** Timing / Δt / sizes enable volume analysis. */
  readonly timing: boolean
  /** Topology-preserving IP / subnet structure (diagnostic). */
  readonly topology: boolean
  /** TCP/IP fingerprint residuals (TTL, window, options, …). */
  readonly fingerprint: boolean
}

function hasFlag(flags: readonly PrivacyRiskFlag[], flag: PrivacyRiskFlag): boolean {
  return flags.includes(flag)
}

/**
 * Derive residual-risk axes from privacy report + profile.
 * high-privacy may still surface some axes (graph/ports) when intentionally kept.
 */
export function buildDiagnosticResidualRisk(input: {
  readonly profile: PcapAnonymizationLevel
  readonly privacy?: Pick<PcapPrivacyReport, 'residualRisks' | 'preservesExactTimestampDeltas' | 'networkFingerprintNormalized'>
}): DiagnosticResidualRisk {
  const flags = input.privacy?.residualRisks ?? []
  const timing =
    hasFlag(flags, 'exact-timestamp-deltas')
    || hasFlag(flags, 'packet-lengths')
    || input.privacy?.preservesExactTimestampDeltas === true
  const fingerprint =
    hasFlag(flags, 'tcp-ip-fingerprint')
    || input.privacy?.networkFingerprintNormalized === false
  const graph = hasFlag(flags, 'communication-graph') || hasFlag(flags, 'service-ports')
  // Topology residual risk: only diagnostic keeps topology-preserving IP mapping.
  // high-privacy uses privacy-preserving IPs — do not claim topology residual from profile alone.
  const topology =
    input.profile === 'diagnostic'
      ? true
      : hasFlag(flags, 'sip-topology-capabilities')

  return { graph, timing, topology, fingerprint }
}
