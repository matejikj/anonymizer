/**
 * VoIP release gate (step 10 / CF-07) — golden corpus, export parity, independent
 * checksum + SIP reparse, no-leak, optional tshark oracle.
 */

import { describe, expect, it } from 'vitest';
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types';
import type { ClassicPcapHeader, PacketEnvelope } from '../../../src/pcap/domain/types';
import { DIAGNOSTIC_POLICY, createPresetProfile } from '../../../src/pcap/profile/presets';
import { runDiscoveryPipeline, identitiesFromDiscovery } from '../../../src/pcap/discovery/discoveryPipeline';
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase';
import { MappingAuthority } from '../../../src/mapping/mappingAuthority';
import { buildDeterministicPlan } from '../../../src/pcap/plan/deterministicPlanBuilder';
import {
  dedupeIdentities,
  identitiesForClosureFailures,
  validateMappingClosure,
} from '../../../src/pcap/plan/mappingClosureValidation';
import { buildCaptureFromPlan } from '../../../src/pcap/export/engine';
import { previewBytesFromPlan } from '../../../src/pcap/export/packetBuilder';
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader';
import { validateClassicPcap } from '../../../src/pcap/capture/validator';
import { locateLayers } from '../../../src/pcap/checksums/locate';
import { buildVoipObservability } from '../../../src/pcap/coverage/voipObservability';
import { parseSipMessage } from '../../../src/pcap/protocols/application/sip';
import { VOIP_SEED_TOKENS, voipCorpusScenarios } from '../fixtures/voipCorpus';
import { assertBufferHasNoVoipLeaks, assertCaptureHasNoVoipLeaks } from '../helpers/voipLeakScan';
import { assertPacketChecksumsValid } from '../helpers/checksumAssert';
import { validateCaptureWithTshark } from '../helpers/externalValidation';

function checksumSkipOffsets(data: Uint8Array, linkType: number): Set<number> {
  const skip = new Set<number>();
  const layers = locateLayers(data, linkType, data.length);
  if (layers.l3Proto === 'ipv4') skip.add(layers.l3Offset + 10).add(layers.l3Offset + 11);
  if (layers.l4Proto === 'tcp') skip.add(layers.l4Offset + 16).add(layers.l4Offset + 17);
  if (layers.l4Proto === 'udp') skip.add(layers.l4Offset + 6).add(layers.l4Offset + 7);
  if (layers.l4Proto === 'icmpv4') skip.add(layers.l4Offset + 2).add(layers.l4Offset + 3);
  return skip;
}

function classicHeader(): ClassicPcapHeader {
  return {
    format: CaptureFormat.ClassicPcap,
    endian: Endian.Little,
    timestampResolution: TimestampResolution.Microseconds,
    versionMajor: 2,
    versionMinor: 4,
    snapLen: 65535,
    linkType: 1,
    tzOffset: 0,
    sigfigs: 0,
  };
}

function runVoipPipeline(packets: readonly PacketEnvelope[], fileName: string) {
  const policy = DIAGNOSTIC_POLICY;
  const profile = createPresetProfile('diagnostic', { id: 'voip-gate', name: 'VoIP gate' });
  const reassembly = runCaptureReassembly(packets, policy);
  const discovery = runDiscoveryPipeline(packets, policy, 'voip-gate', fileName, { reassemblyContext: reassembly });
  const authority = new MappingAuthority({
    ip: profile.mapping.ip,
    mac: profile.mapping.mac,
    timestamps: profile.mapping.timestamps,
    ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
    vlan: profile.mapping.vlan,
  });
  const identities = identitiesFromDiscovery(discovery);
  let resolved = authority.resolve({ generationId: 'voip-gate', sourceId: fileName, identities });
  if (!resolved.ok) throw new Error('mapping resolve failed');
  let unresolvedFailures: import('../../../src/pcap/plan/mappingClosureValidation').MappingClosureFailure[] = [];
  let closure = validateMappingClosure(discovery.intents, resolved.snapshot);
  if (!closure.ok) {
    const topUp = identitiesForClosureFailures(closure.failures);
    resolved = authority.resolve({
      generationId: 'voip-gate',
      sourceId: fileName,
      identities: dedupeIdentities([...identities, ...topUp]),
    });
    if (!resolved.ok) throw new Error('mapping resolve failed');
    closure = validateMappingClosure(discovery.intents, resolved.snapshot);
    if (!closure.ok) unresolvedFailures = [...closure.failures];
  }
  const plan = buildDeterministicPlan({
    generationId: 'voip-gate',
    profile,
    format: CaptureFormat.ClassicPcap,
    fileName,
    packets,
    policy,
    snapshot: resolved.snapshot,
    reassemblyContext: reassembly,
    classicHeader: classicHeader(),
    sourceId: fileName,
    unresolvedClosureFailures: unresolvedFailures,
  });
  return { discovery, plan, packets };
}

function udpOrTcpPayloadOffset(data: Uint8Array, linkType: number): number | null {
  const layers = locateLayers(data, linkType, data.length);
  if (layers.l4Proto === 'udp' && layers.l4Offset + 8 <= data.length) return layers.l4Offset + 8;
  if (layers.l4Proto === 'tcp' && layers.l4Offset + 20 <= data.length) {
    const dataOff = layers.l4Offset + ((data[layers.l4Offset + 12]! >> 4) * 4);
    return dataOff <= data.length ? dataOff : null;
  }
  return null;
}

/** Independent SIP oracle — must not rely on the sanitizer's own parse result alone. */
function assertIndependentSipReparseWhenPresent(data: Uint8Array, linkType: number): void {
  const payloadOff = udpOrTcpPayloadOffset(data, linkType);
  if (payloadOff === null || payloadOff >= data.length) return;
  const payload = data.subarray(payloadOff);
  const parsed = parseSipMessage(payload);
  if (parsed.kind === 'not-sip') return;
  expect(
    parsed.kind === 'complete' || parsed.kind === 'incomplete',
    `SIP reparse must not be malformed (${parsed.kind}: ${'reason' in parsed ? parsed.reason : ''})`,
  ).toBe(true);
  if (parsed.kind === 'complete') {
    expect(parsed.message.headers.length).toBeGreaterThan(0);
  }
}

describe('VoIP release gate (step 10 / CF-07)', () => {
  for (const scenario of voipCorpusScenarios()) {
    it(`corpus ${scenario.id}: export parity, checksums, SIP reparse, no-leak`, () => {
      const { plan, packets } = runVoipPipeline(scenario.packets, `${scenario.id}.pcap`);
      const built = buildCaptureFromPlan(plan, packets);
      expect(built.validationValid).toBe(true);
      expect(built.validationIssueCount).toBe(0);

      const validation = validateClassicPcap(built.buffer);
      expect(validation.valid).toBe(true);

      const reread = readClassicPcap(built.buffer);
      expect(reread.packets.length).toBeGreaterThan(0);
      assertCaptureHasNoVoipLeaks(built.buffer, VOIP_SEED_TOKENS);

      let exportIndex = 0;
      for (let i = 0; i < packets.length; i++) {
        const planPkt = plan.packets[i]!;
        if (planPkt.drop) continue;
        const preview = previewBytesFromPlan(packets[i]!, planPkt);
        const exported = reread.packets[exportIndex]!.data;
        exportIndex++;
        const skip = checksumSkipOffsets(exported, planPkt.linkType);
        expect(exported.length).toBe(preview.length);
        for (let b = 0; b < preview.length; b++) {
          if (skip.has(b)) continue;
          expect(exported[b]).toBe(preview[b]);
        }
        assertBufferHasNoVoipLeaks(exported, VOIP_SEED_TOKENS);
        assertPacketChecksumsValid(exported, planPkt.linkType);
        assertIndependentSipReparseWhenPresent(exported, planPkt.linkType);
      }

      if (scenario.expectMediaDropped) {
        const dropped = plan.packets.filter((p) => p.drop).length;
        expect(dropped).toBeGreaterThan(0);
      }
    });
  }

  it('observability summary separates SIP, media, encryption, and reassembly', () => {
    const scenario = voipCorpusScenarios().find((s) => s.id === 'udp-invite-sdp-rtp-rtcp')!;
    const { discovery } = runVoipPipeline(scenario.packets, 'observability.pcap');
    const summary = buildVoipObservability({
      unifiedCoverage: discovery.unifiedCoverage,
      packetDiscovery: discovery.packetDiscovery,
      analysis: discovery.analysis,
    });
    expect(summary.sipPacketCount).toBeGreaterThan(0);
    expect(summary.rtpStrippedCount + summary.rtcpStrippedCount).toBeGreaterThan(0);
    expect(summary.rtpDroppedCount + summary.rtcpDroppedCount).toBe(0);
    expect(summary.mediaFlowCount).toBeGreaterThan(0);
  });

  it('leak scan catches base64-encoded seed fragments', () => {
    const encoded = Buffer.from(VOIP_SEED_TOKENS[0]!, 'latin1').toString('base64');
    const buf = new Uint8Array(Buffer.from(`prefix-${encoded}-suffix`, 'latin1'));
    expect(() => assertBufferHasNoVoipLeaks(buf, VOIP_SEED_TOKENS)).toThrow();
  });

  it('tshark/capinfos accepts corpus export when tool is available', async () => {
    const scenario = voipCorpusScenarios().find((s) => s.id === 'udp-invite-sdp-rtp-rtcp')!;
    const { plan, packets } = runVoipPipeline(scenario.packets, 'tshark-gate.pcap');
    const built = buildCaptureFromPlan(plan, packets);
    const ext = await validateCaptureWithTshark(built.buffer, built.fileName);
    if (ext.available) {
      expect(ext.valid, ext.output).toBe(true);
    }
  });
});
