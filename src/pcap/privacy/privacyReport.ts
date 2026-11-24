/**
 * CF-15 — privacy report derived from plan + policy + coverage (not preset name alone).
 */

import type { PcapPlanSnapshot } from '../export/planSnapshot';
import type { LayerCoverage, SanitizationPolicy } from '../sanitize/types';
import type { PcapAnonymizationLevel } from '../profile/pcapAnonymizationLevel';
import {
  threatProfileForPreset,
  type AdversaryModel,
  type PrivacyRiskFlag,
  type TransformationKind,
} from './threatModel';
import { timestampModeFromConfig } from '../anonymization/timestampMapping';

export interface PcapPrivacyReport {
  readonly format: 'rnd-log-anonymizer-pcap-privacy-report';
  readonly schemaVersion: 1;
  readonly pcapLevel: PcapAnonymizationLevel;
  /** @deprecated Prefer pcapLevel. */
  readonly preset: string;
  readonly transformationKind: TransformationKind;
  readonly protectsAgainst: readonly AdversaryModel[];
  readonly doesNotProtectAgainst: readonly AdversaryModel[];
  readonly residualRisks: readonly PrivacyRiskFlag[];
  readonly timestampMode: string;
  readonly preservesExactTimestampDeltas: boolean;
  readonly networkFingerprintNormalized: boolean;
  readonly mediaPolicy: string;
  readonly servicePortsPreserved: true;
  readonly communicationGraphPreserved: true;
  readonly packetLengthsPreserved: true;
  readonly preservedUnsafeSpanCount: number;
  readonly requiresUnsafeConfirmation: boolean;
  /** Set when the operator explicitly confirmed a non-green export (no original values). */
  readonly unsafeExportAcknowledged: boolean;
  readonly notes: string;
}

export interface BuildPrivacyReportInput {
  readonly plan: PcapPlanSnapshot;
  readonly pcapLevel?: PcapAnonymizationLevel;
  readonly profile?: { readonly preset: PcapAnonymizationLevel; readonly mediaPolicy: SanitizationPolicy['mediaPolicy']; readonly mapping: { readonly timestamps: import('../anonymization/timestampMapping').TimestampMappingConfig } };
  readonly policy: SanitizationPolicy;
  /** Flattened coverage from discovery / sanitization (may be empty). */
  readonly coverage?: readonly LayerCoverage[];
  readonly unsafeExportAcknowledged?: boolean;
}

export function countPreservedUnsafeSpans(coverage: readonly LayerCoverage[]): number {
  let n = 0;
  for (const span of coverage) {
    if (span.status === 'preserved-unsafe') n += span.aggregateCount ?? 1;
  }
  return n;
}

export function buildPrivacyReport(input: BuildPrivacyReportInput): PcapPrivacyReport {
  const level = input.pcapLevel ?? input.plan.pcapLevel ?? input.profile?.preset ?? input.policy.preset
  const threat = threatProfileForPreset(level);
  const tsMode = timestampModeFromConfig(
    input.plan.timestamps ?? input.profile?.mapping.timestamps ?? 'relative',
  );
  const preservesExact = tsMode === 'relative-exact';
  const fp = input.policy.networkFingerprint;
  const fingerprintNormalized =
    fp.ttl === 'normalize' && fp.tcpWindow === 'normalize' && fp.flowLabel === 'normalize'
    && fp.tcpOptions === 'normalize';
  const fingerprintMapped =
    fp.ipv4Id === 'map' && fp.tcpSeq === 'map' && (fp.flowLabel === 'map' || fp.flowLabel === 'normalize');
  const coverage = input.coverage ?? [];
  const preservedUnsafeSpanCount = countPreservedUnsafeSpans(coverage);
  const mediaPolicy = input.profile?.mediaPolicy ?? input.policy.mediaPolicy;
  const mediaUnsafe = mediaPolicy === 'preserve-unsafe';

  const residual = new Set<PrivacyRiskFlag>(threat.intentionalResiduals);
  // Always true for length-preserving engine
  residual.add('packet-lengths');
  residual.add('communication-graph');
  residual.add('service-ports');

  if (preservesExact) residual.add('exact-timestamp-deltas');
  else residual.delete('exact-timestamp-deltas');

  if (!fingerprintNormalized) residual.add('tcp-ip-fingerprint');
  else residual.delete('tcp-ip-fingerprint');

  if (mediaUnsafe) residual.add('media-preserved-unsafe');
  else residual.delete('media-preserved-unsafe');

  if (preservedUnsafeSpanCount > 0) residual.add('preserved-unsafe-spans');
  else if (!mediaUnsafe) residual.delete('preserved-unsafe-spans');

  // Step 7/9: diagnostic TTL/window residuals and mapped SEQ/ID do not require unsafe ack.
  const requiresUnsafeConfirmation =
    mediaUnsafe
    || preservedUnsafeSpanCount > 0
    || (!fingerprintNormalized && !fingerprintMapped && fp.ttl === 'preserve-unsafe');

  return {
    format: 'rnd-log-anonymizer-pcap-privacy-report',
    schemaVersion: 1,
    pcapLevel: level,
    preset: level,
    transformationKind: threat.transformationKind,
    protectsAgainst: threat.protectsAgainst,
    doesNotProtectAgainst: threat.doesNotProtectAgainst,
    residualRisks: [...residual].sort(),
    timestampMode: tsMode,
    preservesExactTimestampDeltas: preservesExact,
    networkFingerprintNormalized: fingerprintNormalized,
    mediaPolicy,
    servicePortsPreserved: true,
    communicationGraphPreserved: true,
    packetLengthsPreserved: true,
    preservedUnsafeSpanCount,
    requiresUnsafeConfirmation,
    unsafeExportAcknowledged: input.unsafeExportAcknowledged === true,
    notes: threat.notes,
  };
}

/**
 * Fail closed when the privacy report contradicts the immutable plan/policy.
 */
export function assertPrivacyReportMatchesPlan(
  report: PcapPrivacyReport,
  input: BuildPrivacyReportInput,
): void {
  const expected = buildPrivacyReport({
    ...input,
    unsafeExportAcknowledged: report.unsafeExportAcknowledged,
  });

  if (report.preservesExactTimestampDeltas !== expected.preservesExactTimestampDeltas) {
    throw new Error('Privacy report timestamp residual does not match plan timestamp mode');
  }
  if (report.networkFingerprintNormalized !== expected.networkFingerprintNormalized) {
    throw new Error('Privacy report fingerprint claim does not match policy');
  }
  if (report.mediaPolicy !== expected.mediaPolicy) {
    throw new Error('Privacy report mediaPolicy does not match profile');
  }
  if (report.preservedUnsafeSpanCount !== expected.preservedUnsafeSpanCount) {
    throw new Error('Privacy report preserved-unsafe count does not match coverage');
  }
  if (report.requiresUnsafeConfirmation !== expected.requiresUnsafeConfirmation) {
    throw new Error('Privacy report unsafe-confirmation flag does not match plan evidence');
  }
  if (report.requiresUnsafeConfirmation && !report.unsafeExportAcknowledged) {
    throw new Error('Unsafe export requires explicit acknowledgement in the privacy report');
  }
  const a = [...report.residualRisks].sort().join(',');
  const b = [...expected.residualRisks].sort().join(',');
  if (a !== b) {
    throw new Error('Privacy report residualRisks do not match derived plan evidence');
  }
}
