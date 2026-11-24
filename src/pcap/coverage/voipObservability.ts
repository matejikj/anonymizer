/**
 * VoIP observability summary for coverage UI (step 10).
 */

import type { AnalysisResult } from '../protocols/analysis';
import type { PacketDiscoveryResult } from '../discovery/types';
import type { UnifiedCoverageModel } from './types';

const VOIP_PROTOCOLS = new Set([
  'sip',
  'sdp',
  'rtp',
  'rtcp',
  'srtp',
  'sip-tls',
  'tls',
  'tls-clienthello',
  'tls-serverhello',
  'tls-certificate',
  'tls-handshake-unsupported',
  'tls-encrypted-payload',
]);

export interface VoipObservabilitySummary {
  readonly sipPacketCount: number;
  readonly dialogCount: number;
  readonly mediaFlowCount: number;
  readonly rtpDroppedCount: number;
  readonly rtcpDroppedCount: number;
  /** Confirmed media kept with strip-payload / redacted coverage. */
  readonly rtpStrippedCount: number;
  readonly rtcpStrippedCount: number;
  readonly encryptedCount: number;
  readonly preservedUnsafeMediaCount: number;
  readonly reassemblyCount: number;
  readonly incompleteReasons: readonly string[];
}

export function buildVoipObservability(input: {
  readonly unifiedCoverage: UnifiedCoverageModel;
  readonly packetDiscovery: readonly PacketDiscoveryResult[];
  readonly analysis: AnalysisResult;
}): VoipObservabilitySummary {
  const sipPackets = new Set<number>();
  let rtpDroppedCount = 0;
  let rtcpDroppedCount = 0;
  let rtpStrippedCount = 0;
  let rtcpStrippedCount = 0;
  let encryptedCount = 0;
  let preservedUnsafeMediaCount = 0;
  let reassemblyCount = 0;
  const mediaFlows = new Set<string>();
  const incompleteReasons = new Set<string>();

  for (let i = 0; i < input.unifiedCoverage.perPacket.length; i++) {
    const spans = input.unifiedCoverage.perPacket[i] ?? [];
    for (const span of spans) {
      if (!VOIP_PROTOCOLS.has(span.protocol)) continue;
      sipPackets.add(i);
      if (span.protocol === 'sip' || span.protocol === 'sdp') {
        if (span.status === 'requires-reassembly') {
          reassemblyCount++;
          incompleteReasons.add('requires-reassembly');
        }
        if (span.status === 'malformed') incompleteReasons.add('malformed-sip');
      }
      if (span.status === 'encrypted') encryptedCount++;
      if (span.status === 'preserved-unsafe') preservedUnsafeMediaCount++;
      if (span.protocol === 'rtp' || span.protocol === 'rtcp' || span.protocol === 'srtp') {
        mediaFlows.add(`${span.protocol}:${i}`);
        if (span.status === 'redacted') {
          if (span.protocol === 'rtp' || span.protocol === 'srtp') rtpStrippedCount++;
          if (span.protocol === 'rtcp') rtcpStrippedCount++;
        }
      }
    }
  }

  for (const pd of input.packetDiscovery) {
    if (pd.drop) {
      for (const span of pd.coverage) {
        if (span.protocol === 'rtp' || span.protocol === 'srtp') rtpDroppedCount++;
        if (span.protocol === 'rtcp') rtcpDroppedCount++;
      }
    }
    for (const issue of pd.issues) {
      if (/reassembly|incomplete|SIP/i.test(issue)) incompleteReasons.add(issue);
    }
  }

  const dialogIds = new Set<string>();
  for (const entity of input.analysis.entities) {
    if (entity.category === 'sip-call-id') dialogIds.add(entity.value);
  }

  return {
    sipPacketCount: sipPackets.size,
    dialogCount: dialogIds.size,
    mediaFlowCount: mediaFlows.size,
    rtpDroppedCount,
    rtcpDroppedCount,
    rtpStrippedCount,
    rtcpStrippedCount,
    encryptedCount,
    preservedUnsafeMediaCount,
    reassemblyCount,
    incompleteReasons: [...incompleteReasons],
  };
}

export function formatVoipObservabilityLines(
  summary: VoipObservabilitySummary,
  labels: {
    readonly line: (key: string, params: Record<string, string | number>) => string;
  },
): string[] {
  const lines: string[] = [];
  lines.push(labels.line('sipMessages', { n: summary.sipPacketCount }));
  lines.push(labels.line('dialogs', { n: summary.dialogCount }));
  lines.push(labels.line('mediaFlows', { n: summary.mediaFlowCount }));
  if (summary.rtpDroppedCount + summary.rtcpDroppedCount > 0) {
    lines.push(labels.line('mediaDropped', {
      rtp: summary.rtpDroppedCount,
      rtcp: summary.rtcpDroppedCount,
    }));
  }
  if (summary.rtpStrippedCount + summary.rtcpStrippedCount > 0) {
    lines.push(labels.line('mediaStripped', {
      rtp: summary.rtpStrippedCount,
      rtcp: summary.rtcpStrippedCount,
    }));
  }
  if (summary.preservedUnsafeMediaCount > 0) {
    lines.push(labels.line('mediaPreservedUnsafe', { n: summary.preservedUnsafeMediaCount }));
  }
  if (summary.encryptedCount > 0) {
    lines.push(labels.line('encrypted', { n: summary.encryptedCount }));
  }
  if (summary.reassemblyCount > 0) {
    lines.push(labels.line('reassembly', { n: summary.reassemblyCount }));
  }
  if (summary.incompleteReasons.length > 0) {
    lines.push(labels.line('incomplete', { n: summary.incompleteReasons.length }));
  }
  return lines;
}
