/**
 * SIP discovery/sanitization over reassembled buffers (step 9).
 */

import { PatchCollector } from '../sanitize/PatchCollector';
import type { MappingLike } from '../anonymization/mapping';
import { FingerprintSession } from '../anonymization/fingerprintSession';
import type { LayerCoverage, BytePatch } from '../sanitize/types';
import { IntentCollector } from '../discovery/intentCollector';
import { MediaFlowIndex } from '../discovery/mediaFlowIndex';
import { parseSipMessages } from '../protocols/application/sip/parser';
import { isSipPortHint } from '../protocols/application/sip/classify';
import { recordSipSdpDiscoveryIntents } from '../protocols/application/sip/discoverIntents';
import { sanitizeStructuredSipMessage } from '../protocols/application/sip/sanitizeApply';
import { planSipBodyOperations } from '../protocols/application/sip/bodyOperations';
import { emitSiprecMetadataKernelFacts } from '../kernel/siprecKernelFacts';
import type { SemanticJournalBuilder } from '../kernel/journal';
import { looksLikeHttpBuffer } from '../sanitize/http';
import { sanitizeHttpReassembledView } from './httpOverReassembled';
import type { ByteProvenance, PacketReassemblyOverlay, ReassembledView } from './types';
import {
  mergeProjectedPatches,
  projectEntityIntent,
  projectPatches,
} from './patchProject';

export interface SipReassemblyProcessResult {
  readonly overlays: Map<number, PacketReassemblyOverlay>;
  readonly mediaFlowIndex: MediaFlowIndex;
}

/** Discovery pass — intents and coverage only (no mapping patches). */
export function processSipOverReassembledView(
  view: ReassembledView,
  transport: 'tcp' | 'udp',
  primaryPacketIndex: number,
  payloadOffsetOnPrimary: number,
  mediaFlowIndex: MediaFlowIndex,
  options?: { readonly journal?: SemanticJournalBuilder },
): SipReassemblyProcessResult {
  const overlays = new Map<number, PacketReassemblyOverlay>();
  const intents = new IntentCollector();
  const coverage: LayerCoverage[] = [];
  const issues: string[] = [];

  const stream = parseSipMessages(view.bytes);
  if (stream.messages.length === 0) {
    const tailKind = stream.tail?.kind ?? 'not-sip';
    if (tailKind === 'incomplete' || tailKind === 'malformed') {
      markAllPackets(view, overlays, {
        patches: [],
        coverage: [{
          protocol: 'sip',
          offset: payloadOffsetOnPrimary,
          length: view.bytes.length,
          status: tailKind === 'malformed' ? 'malformed' : 'requires-reassembly',
        }],
        issues: [`SIP ${tailKind} on reassembled ${transport} stream`],
        drop: false,
        intents: [],
        skipAppLayer: true,
      });
    }
    return { overlays, mediaFlowIndex };
  }

  for (const entry of stream.messages) {
    mediaFlowIndex.registerFromSipMessage(entry.message, view.bytes);
    recordSipSdpDiscoveryIntents(intents, view.bytes, entry.message, transport, primaryPacketIndex);
    const body = entry.message.body;
    const msgStart = entry.message.span.offset;
    const headersEnd = body ? body.span.offset : entry.message.span.offset + entry.message.span.length;
    coverage.push({
      protocol: 'sip',
      offset: msgStart,
      length: Math.max(0, headersEnd - msgStart),
      status: 'covered',
    });
    const bodyPlan = planSipBodyOperations(entry.message, view.bytes);
    for (const region of bodyPlan.coverage) {
      coverage.push(region);
    }
    if (options?.journal) {
      emitSiprecMetadataKernelFacts({
        message: entry.message,
        buffer: view.bytes,
        packetIndex: primaryPacketIndex,
        logicalMessageId: primaryPacketIndex,
        journal: options.journal,
      })
    }
  }

  const projectedIntents: Array<{ packetIndex: number; intent: import('../discovery/types').TransformationIntent }> = [];
  for (const intent of intents.intents) {
    if (intent.kind === 'entity-replacement') {
      projectedIntents.push(...projectEntityIntent(view.provenance, intent));
    } else {
      projectedIntents.push({ packetIndex: intent.packetIndex, intent });
    }
  }

  const intentsByPacket = new Map<number, import('../discovery/types').TransformationIntent[]>();
  for (const { packetIndex, intent } of projectedIntents) {
    const list = intentsByPacket.get(packetIndex) ?? [];
    list.push(intent);
    intentsByPacket.set(packetIndex, list);
  }

  for (const packetIndex of view.packetIndices) {
    const packetIntents = intentsByPacket.get(packetIndex) ?? [];
    overlays.set(packetIndex, {
      patches: [],
      coverage: coverage.map((c) => ({
        ...c,
        offset: projectCoverageOffset(view.provenance, c.offset, packetIndex, payloadOffsetOnPrimary),
      })).filter((c) => c.length > 0),
      issues: [...issues],
      drop: false,
      intents: packetIntents,
      skipAppLayer: true,
    });
  }

  return { overlays, mediaFlowIndex };
}

function projectCoverageOffset(
  provenance: readonly ByteProvenance[],
  assembledOffset: number,
  packetIndex: number,
  fallback: number,
): number {
  for (const span of provenance) {
    if (span.packetIndex !== packetIndex) continue;
    if (assembledOffset >= span.assembledOffset && assembledOffset < span.assembledOffset + span.length) {
      return span.packetOffset + (assembledOffset - span.assembledOffset);
    }
  }
  return fallback;
}

function markAllPackets(
  view: ReassembledView,
  overlays: Map<number, PacketReassemblyOverlay>,
  overlay: PacketReassemblyOverlay,
): void {
  for (const packetIndex of view.packetIndices) {
    overlays.set(packetIndex, overlay);
  }
}

export function looksLikeSipOnPort(srcPort: number, dstPort: number): boolean {
  return isSipPortHint(srcPort, dstPort);
}

/** Plan/export pass — sanitize with real mapping and project patches (SIP + HTTP). */
export function sanitizeReassembledView(
  view: ReassembledView,
  mapping: MappingLike,
  transport: 'tcp' | 'udp',
  payloadTime?: import('../kernel/payloadTimeCodec').PayloadTimeSession,
): Map<number, BytePatch[]> {
  if (view.status !== 'complete' || view.bytes.length === 0) {
    return new Map();
  }

  if (looksLikeHttpBuffer(view.bytes)) {
    return sanitizeHttpReassembledView(view, mapping, payloadTime);
  }

  try {
    const collector = new PatchCollector(view.bytes.length);
    const stream = parseSipMessages(view.bytes);
    for (const entry of stream.messages) {
      try {
        sanitizeStructuredSipMessage(view.bytes, entry.message, transport, collector, mapping);
      } catch {
        // T07: one SIP message in the stream — mask remaining unprocessed span best-effort
        // via deferred resolve; do not abort sibling messages already collected.
      }
    }
    // PF-06: SIP/SDP entity patches are deferred (see sanitizeApply.ts) — resolve them now
    // against the real mapping. No TCP-header fingerprint fields exist at this (application)
    // layer, so a throwaway FingerprintSession is fine — no deferred closure here reads it.
    // T14 — payloadTime for SIP Date absolute-time rewrite.
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession(), payloadTime });

    return mergeProjectedPatches(projectPatches(view.provenance, collector.getPatches()));
  } catch {
    // Entire reassembled view failed — caller skips this flow; other flows continue.
    return new Map();
  }
}
