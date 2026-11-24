/**
 * Provenance tracking and patch/intent projection (step 9).
 */

import type { BytePatch } from '../sanitize/types';
import type { TransformationIntent } from '../discovery/types';
import type { ByteProvenance } from './types';

export interface ProjectedPatch {
  readonly packetIndex: number;
  readonly patch: BytePatch;
}

export interface ProjectedIntent {
  readonly packetIndex: number;
  readonly intent: TransformationIntent;
}

/** Project a patch on the reassembled buffer back to source packets. */
export function projectPatch(
  provenance: readonly ByteProvenance[],
  assembledOffset: number,
  data: Uint8Array,
): ProjectedPatch[] {
  const out: ProjectedPatch[] = [];
  const end = assembledOffset + data.length;

  for (const span of provenance) {
    const spanEnd = span.assembledOffset + span.length;
    const overlapStart = Math.max(assembledOffset, span.assembledOffset);
    const overlapEnd = Math.min(end, spanEnd);
    if (overlapStart >= overlapEnd) continue;

    const localStart = overlapStart - assembledOffset;
    const localSpanStart = overlapStart - span.assembledOffset;
    const overlapLen = overlapEnd - overlapStart;

    out.push({
      packetIndex: span.packetIndex,
      patch: {
        offset: span.packetOffset + localSpanStart,
        data: data.slice(localStart, localStart + overlapLen),
      },
    });
  }

  return out;
}

export function projectPatches(
  provenance: readonly ByteProvenance[],
  patches: readonly BytePatch[],
): ProjectedPatch[] {
  const out: ProjectedPatch[] = [];
  for (const patch of patches) {
    out.push(...projectPatch(provenance, patch.offset, patch.data));
  }
  return out;
}

export function projectEntityIntent(
  provenance: readonly ByteProvenance[],
  intent: Extract<TransformationIntent, { kind: 'entity-replacement' }>,
): ProjectedIntent[] {
  const out: ProjectedIntent[] = [];
  const end = intent.offset + intent.byteLength;

  for (const span of provenance) {
    const spanEnd = span.assembledOffset + span.length;
    const overlapStart = Math.max(intent.offset, span.assembledOffset);
    const overlapEnd = Math.min(end, spanEnd);
    if (overlapStart >= overlapEnd) continue;

    const localSpanStart = overlapStart - span.assembledOffset;
    const overlapLen = overlapEnd - overlapStart;

    out.push({
      packetIndex: span.packetIndex,
      intent: {
        ...intent,
        packetIndex: span.packetIndex,
        offset: span.packetOffset + localSpanStart,
        byteLength: overlapLen,
      },
    });
  }

  return out;
}

export function mergeProjectedPatches(projected: readonly ProjectedPatch[]): Map<number, BytePatch[]> {
  const byPacket = new Map<number, BytePatch[]>();
  for (const { packetIndex, patch } of projected) {
    const list = byPacket.get(packetIndex) ?? [];
    list.push(patch);
    byPacket.set(packetIndex, list);
  }
  for (const [idx, patches] of byPacket) {
    patches.sort((a, b) => a.offset - b.offset);
    byPacket.set(idx, patches);
  }
  return byPacket;
}
