/**
 * DMR sanitizer — Homebrew/MMDVM "DMRD" data packet.
 *
 * This is an open, publicly-documented UDP protocol used by DMR reflectors/gateways
 * (HBlink, FreeDMR, BrandMeister-style) — unlike MOTOTRBO's proprietary IPSC format
 * (see mototrbo.ts), its 20-byte header is well-specified enough to parse safely.
 *
 * Only the source/destination radio IDs (subscriber/talkgroup) are mapped — the AMBE
 * voice payload is left untouched. Voice is opaque and not meaningfully anonymizable;
 * touching it would also contradict this engine's "replayable anonymized traffic"
 * non-goal (voice payload rewrite is out of scope).
 */

import type { PatchCollector } from './PatchCollector';
import type { MappingLike } from '../anonymization/mapping';
import type { AppLayerResult } from './types';

const DMRD_MAGIC = [0x44, 0x4d, 0x52, 0x44]; // ASCII "DMRD"
const DMRD_HEADER_LEN = 20; // magic(4) + seq(1) + srcId(3) + dstId(3) + repeaterId(4) + flags(1) + streamId(4)

export function sanitizeDmr(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
): AppLayerResult | null {
  if (length < DMRD_HEADER_LEN) return null;
  for (let i = 0; i < DMRD_MAGIC.length; i++) {
    if (buffer[offset + i] !== DMRD_MAGIC[i]) return null;
  }

  patchRadioId(buffer, offset + 5, collector, mapping); // srcId (3 bytes BE)
  patchRadioId(buffer, offset + 8, collector, mapping); // dstId (3 bytes BE)

  // Header mapped; AMBE voice is intentionally preserved (opaque, not anonymizable).
  return {
    coverage: [
      { protocol: 'dmr', offset, length: DMRD_HEADER_LEN, status: 'covered' },
      ...(length > DMRD_HEADER_LEN
        ? [{
            protocol: 'dmr-voice' as const,
            offset: offset + DMRD_HEADER_LEN,
            length: length - DMRD_HEADER_LEN,
            status: 'preserved-unsafe' as const,
          }]
        : []),
    ],
  };
}

function patchRadioId(buffer: Uint8Array, offset: number, collector: PatchCollector, _mapping: MappingLike): void {
  const id = (buffer[offset]! << 16) | (buffer[offset + 1]! << 8) | buffer[offset + 2]!;
  try {
    collector.addDeferred(offset, 3, ({ mapping: liveMapping }) => {
      const mapped = parseInt(liveMapping.map('radioId', `${id}`), 10);
      return new Uint8Array([(mapped >> 16) & 0xff, (mapped >> 8) & 0xff, mapped & 0xff]);
    });
  } catch { /* overlap */ }
}
