/**
 * Profile change impact classifier from canonical effective policy (Stage 26).
 */

import {
  ProfileImpactKind,
  type ProfileImpact,
} from '../../pcap/profile/profileImpact'
import type { CorrelationEffectivePolicy } from './types'

export function classifyProfileImpact(
  before: CorrelationEffectivePolicy,
  after: CorrelationEffectivePolicy,
): ProfileImpact {
  if (before.representationHash !== after.representationHash) {
    return {
      kind: ProfileImpactKind.RepresentationPolicy,
      reasonKey: 'representation-policy-changed',
    }
  }
  if (before.discoveryHash !== after.discoveryHash) {
    return {
      kind: ProfileImpactKind.Discovery,
      reasonKey: 'discovery-policy-changed',
    }
  }
  if (before.policyHash !== after.policyHash) {
    return {
      kind: ProfileImpactKind.CoverageOnly,
      reasonKey: 'coverage-metadata-changed',
    }
  }
  return {
    kind: ProfileImpactKind.ExportOnly,
    reasonKey: 'no-policy-change',
  }
}

export function classifyPcapPayloadPolicyChange(
  beforePayload: string,
  afterPayload: string,
): ProfileImpact {
  if (beforePayload !== afterPayload) {
    return {
      kind: ProfileImpactKind.CoverageOnly,
      reasonKey: 'payload-policy-changed',
    }
  }
  return {
    kind: ProfileImpactKind.ExportOnly,
    reasonKey: 'no-payload-change',
  }
}

export { ProfileImpactKind, type ProfileImpact, profileImpactBlocksExport } from '../../pcap/profile/profileImpact'
