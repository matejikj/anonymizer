/**
 * T17/V15 — sanitize complete SCTP user messages and project patches onto fragment packets.
 */

import type { MappingLike } from '../anonymization/mapping';
import { FingerprintSession } from '../anonymization/fingerprintSession';
import { IntentCollector } from '../discovery/intentCollector';
import { PassthroughMapping } from '../discovery/passthroughMapping';
import { PatchCollector } from '../sanitize/PatchCollector';
import type { BytePatch, LayerCoverage } from '../sanitize/types';
import { sanitizeSctpUserMessage } from '../sanitize/sctp';
import type { PacketReassemblyOverlay, ReassembledView } from './types';
import { mergeProjectedPatches, projectEntityIntent, projectPatches } from './patchProject';

/**
 * Discovery pass — record PPID-dispatch coverage/intents on the reassembled buffer and
 * project them onto source packets (no concrete mapping patches yet).
 */
export function processSctpOverReassembledView(
  view: ReassembledView,
): Map<number, PacketReassemblyOverlay> {
  const overlays = new Map<number, PacketReassemblyOverlay>();
  if (view.status !== 'complete' || view.transport !== 'sctp' || !view.sctp) {
    return overlays;
  }
  if (view.bytes.length === 0) return overlays;

  const intents = new IntentCollector();
  const collector = new PatchCollector(view.bytes.length);
  const passthrough = new PassthroughMapping();
  const primaryIndex = view.packetIndices[0] ?? 0;
  const result = sanitizeSctpUserMessage(
    view.bytes,
    0,
    view.bytes.length,
    view.sctp.ppid,
    collector,
    passthrough,
    primaryIndex,
    intents,
    view.sctp.assocKey,
  );

  const coverage = projectCoverageToPackets(view, result.coverage);
  const projectedIntents: Array<{
    packetIndex: number;
    intent: import('../discovery/types').TransformationIntent;
  }> = [];
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
    overlays.set(packetIndex, {
      patches: [],
      coverage: coverage.get(packetIndex) ?? [],
      issues: [...result.issues, 'sctp-message-reassembled'],
      drop: false,
      intents: intentsByPacket.get(packetIndex) ?? [],
      skipAppLayer: false,
    });
  }

  return overlays;
}

/** Plan/export pass — sanitize with real mapping and project length-preserving patches. */
export function sanitizeSctpReassembledView(
  view: ReassembledView,
  mapping: MappingLike,
): Map<number, BytePatch[]> {
  if (view.status !== 'complete' || view.transport !== 'sctp' || !view.sctp) {
    return new Map();
  }
  if (view.bytes.length === 0) return new Map();

  try {
    const collector = new PatchCollector(view.bytes.length);
    const primaryIndex = view.packetIndices[0] ?? 0;
    sanitizeSctpUserMessage(
      view.bytes,
      0,
      view.bytes.length,
      view.sctp.ppid,
      collector,
      mapping,
      primaryIndex,
      undefined,
      view.sctp.assocKey,
    );
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() });
    return mergeProjectedPatches(projectPatches(view.provenance, collector.getPatches()));
  } catch {
    return new Map();
  }
}

function projectCoverageToPackets(
  view: ReassembledView,
  coverage: readonly LayerCoverage[],
): Map<number, LayerCoverage[]> {
  const byPacket = new Map<number, LayerCoverage[]>();
  for (const c of coverage) {
    for (const span of view.provenance) {
      const spanEnd = span.assembledOffset + span.length;
      const overlapStart = Math.max(c.offset, span.assembledOffset);
      const overlapEnd = Math.min(c.offset + c.length, spanEnd);
      if (overlapStart >= overlapEnd) continue;
      const list = byPacket.get(span.packetIndex) ?? [];
      list.push({
        protocol: c.protocol,
        offset: span.packetOffset + (overlapStart - span.assembledOffset),
        length: overlapEnd - overlapStart,
        status: c.status,
      });
      byPacket.set(span.packetIndex, list);
    }
  }
  return byPacket;
}
