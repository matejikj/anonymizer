/**
 * CF-15 — threat model, privacy report, high-privacy preset.
 */

import { describe, expect, it } from 'vitest';
import {
  ADVERSARY_MODELS,
  PRESET_THREAT_PROFILES,
  assertPrivacyReportMatchesPlan,
  buildPrivacyReport,
} from '../../../src/pcap/privacy';
import {
  createPresetProfile,
  HIGH_PRIVACY_POLICY,
  HIGH_PRIVACY_PCAP_MAPPING,
  DIAGNOSTIC_POLICY,
} from '../../../src/pcap/profile/presets';
import {
  TimestampMapping,
  timestampModeFromConfig,
} from '../../../src/pcap/anonymization/timestampMapping';
import { CaptureFormat } from '../../../src/pcap/domain/types';
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot';
import { buildExportReport } from '../../../src/pcap/export/report';
import { emptyChecksumCounts } from '../../../src/pcap/checksums/types';
import type { LayerCoverage } from '../../../src/pcap/sanitize/types';

function emptyPlan(
  timestamps: PcapPlanSnapshot['timestamps'] = 'enumerated',
  level: PcapPlanSnapshot['pcapLevel'] = 'high-privacy',
): PcapPlanSnapshot {
  return {
    generationId: 'g-cf15',
    pcapLevel: level,
    profileId: `pcap-${level}`,
    profileHash: 'hash',
    format: CaptureFormat.ClassicPcap,
    fileName: 'cf15.pcap',
    engineVersion: 'test',
    packets: [],
    droppedPacketNumbers: [],
    timestamps,
    timestampAnchorSeed: 'test-anchor-seed',
    changeCategoryTotals: {
      mapped: 0,
      redacted: 0,
      'masked-content': 0,
      'preserved-encrypted': 0,
      'preserved-for-diagnostics': 0,
      'user-requested-drop': 0,
      blocked: 0,
    },
    maskedByteCount: 0,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
  };
}

function okValidation() {
  return {
    validationValid: true,
    validationIssueCount: 0,
    newBlockingIssues: [] as never[],
    preservedBaselineIssues: [] as never[],
  };
}

describe('CF-15 threat model', () => {
  it('defines the four adversary models', () => {
    expect(ADVERSARY_MODELS.map((a) => a.id).sort()).toEqual([
      'casual-recipient',
      'cross-capture-correlation',
      'injection-known-plaintext',
      'inspection',
    ].sort());
  });

  it('labels only diagnostic and high-privacy in threat profiles', () => {
    expect(PRESET_THREAT_PROFILES.diagnostic.transformationKind).toBe('pseudonymization');
    expect(PRESET_THREAT_PROFILES.diagnostic.doesNotProtectAgainst).toContain('inspection');
    expect(PRESET_THREAT_PROFILES['high-privacy'].transformationKind).toBe('pseudonymization');
  });

  it('high-privacy claims resistance to injection timing via enumerated clocks', () => {
    expect(PRESET_THREAT_PROFILES['high-privacy'].protectsAgainst).toContain(
      'injection-known-plaintext',
    );
    expect(PRESET_THREAT_PROFILES['high-privacy'].protectsAgainst).toContain('casual-recipient');
    expect(HIGH_PRIVACY_PCAP_MAPPING.timestamps).toBe('enumerated');
    expect(HIGH_PRIVACY_POLICY.networkFingerprint.ttl).toBe('normalize');
    expect(HIGH_PRIVACY_POLICY.mediaPolicy).toBe('drop');
    expect(createPresetProfile('high-privacy').mapping.timestamps).toBe('enumerated');
  });
});

describe('CF-15 privacy report', () => {
  it('derives residuals from plan+policy, not preset name alone', () => {
    const profile = createPresetProfile('high-privacy');
    const report = buildPrivacyReport({
      plan: emptyPlan('enumerated'),
      profile,
      policy: HIGH_PRIVACY_POLICY,
      coverage: [],
    });
    expect(report.preservesExactTimestampDeltas).toBe(false);
    expect(report.timestampMode).toBe('enumerated');
    expect(report.networkFingerprintNormalized).toBe(true);
    expect(report.requiresUnsafeConfirmation).toBe(false);
    expect(report.residualRisks).toContain('packet-lengths');
    expect(report.residualRisks).toContain('communication-graph');
    expect(report.residualRisks).not.toContain('exact-timestamp-deltas');
    expect(report.residualRisks).not.toContain('tcp-ip-fingerprint');
  });

  it('does not require acknowledgement for diagnostic mapped fingerprints', () => {
    const profile = createPresetProfile('diagnostic');
    const report = buildPrivacyReport({
      plan: emptyPlan('relative'),
      profile,
      policy: DIAGNOSTIC_POLICY,
      coverage: [],
      unsafeExportAcknowledged: false,
    });
    expect(report.requiresUnsafeConfirmation).toBe(false);
    expect(report.networkFingerprintNormalized).toBe(false);
    expect(report.residualRisks).toContain('tcp-ip-fingerprint');
  });

  it('requires acknowledgement when fingerprint spans are preserved-unsafe', () => {
    const profile = createPresetProfile('diagnostic');
    const coverage: LayerCoverage[] = [{
      protocol: 'rtp',
      offset: 0,
      length: 12,
      status: 'preserved-unsafe',
    }];
    const report = buildPrivacyReport({
      plan: emptyPlan('relative'),
      profile,
      policy: DIAGNOSTIC_POLICY,
      coverage,
      unsafeExportAcknowledged: false,
    });
    expect(report.requiresUnsafeConfirmation).toBe(true);
    expect(() => assertPrivacyReportMatchesPlan(report, {
      plan: emptyPlan('relative'),
      profile,
      policy: DIAGNOSTIC_POLICY,
      coverage,
      unsafeExportAcknowledged: false,
    })).toThrow(/acknowledgement/i);
  });

  it('passes assert when unsafe export is acknowledged', () => {
    const profile = createPresetProfile('diagnostic');
    const coverage: LayerCoverage[] = [{
      protocol: 'ipv4-ttl',
      offset: 8,
      length: 1,
      status: 'preserved-unsafe',
    }];
    const input = {
      plan: emptyPlan('relative'),
      profile,
      policy: DIAGNOSTIC_POLICY,
      coverage,
      unsafeExportAcknowledged: true as const,
    };
    const report = buildPrivacyReport(input);
    expect(report.preservedUnsafeSpanCount).toBe(1);
    expect(() => assertPrivacyReportMatchesPlan(report, input)).not.toThrow();
  });

  it('fails assert when residual claims disagree with plan evidence', () => {
    const profile = createPresetProfile('high-privacy');
    const input = {
      plan: emptyPlan('relative-bucketed', 'high-privacy'),
      profile,
      policy: HIGH_PRIVACY_POLICY,
      coverage: [] as LayerCoverage[],
    };
    const report = buildPrivacyReport(input);
    const tampered = { ...report, preservesExactTimestampDeltas: true };
    expect(() => assertPrivacyReportMatchesPlan(tampered, input)).toThrow(/timestamp/i);
  });

  it('embeds privacy section in export report schema v4', () => {
    const profile = createPresetProfile('high-privacy');
    const privacy = buildPrivacyReport({
      plan: emptyPlan('enumerated'),
      profile,
      policy: HIGH_PRIVACY_POLICY,
    });
    const report = buildExportReport({
      plan: emptyPlan('enumerated'),
      exportedFileName: 'cf15.anonymized.pcap',
      changedPackets: 0,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: okValidation(),
      privacy,
    });
    expect(report.schemaVersion).toBe(8);
    expect(report.privacy?.preset).toBe('high-privacy');
    expect(report.privacy?.transformationKind).toBe('pseudonymization');
    const json = JSON.stringify(report);
    expect(json).not.toMatch(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  });
});

describe('CF-15 high-privacy timing coarsening', () => {
  it('enumerated mode erases unique inter-packet delta patterns', () => {
    expect(timestampModeFromConfig('enumerated')).toBe('enumerated');
    const tm = new TimestampMapping({
      mode: 'enumerated',
      anchorSeconds: 1_700_000_000n,
      enumeratedStepTicks: 1_000_000n, // 1s in µs resolution
    });
    const ups = 1_000_000n;
    // Injection canary: irregular gaps — must become constant enumerated step.
    const base = 100_000_000n;
    const inputs = [0n, 1_000n, 8_000n, 10_000n].map((delta) => ({
      ticks: base + delta,
      unitsPerSecond: ups,
      offsetSeconds: 0n,
    }));
    const mapped = inputs.map((ts) => tm.mapTicks(ts).ticks);
    const d1 = mapped[1]! - mapped[0]!;
    const d2 = mapped[2]! - mapped[1]!;
    const d3 = mapped[3]! - mapped[2]!;
    expect(d1).toBe(d2);
    expect(d2).toBe(d3);
    expect(d1).toBe(1_000_000n);
    expect(d1).not.toBe(1_000n);
    expect(d1).not.toBe(7_000n);
  });
});
