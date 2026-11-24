/**
 * DMR sanitizer — Homebrew/MMDVM "DMRD" data packet.
 *
 * Open, publicly-documented UDP protocol used by DMR reflectors/gateways
 * (HBlink, FreeDMR, BrandMeister-style). Maps source/destination radio IDs.
 *
 * T68 — AMBE voice is never preserve-unsafe on fixed levels:
 * diagnostic (`strip-payload`) masks in place (length/timing kept);
 * high-privacy (`drop`) marks voice unsupported so the export boundary truncates
 * after the header. Status `redacted` / boundary truncate; reason `media-stripped`.
 */

import type { PatchCollector } from './PatchCollector';
import type { MappingLike } from '../anonymization/mapping';
import type { IntentCollector } from '../discovery/intentCollector';
import type { AppLayerResult, SanitizationPolicy } from './types';
import { createMaskFill } from './maskFill';

const DMRD_MAGIC = [0x44, 0x4d, 0x52, 0x44]; // ASCII "DMRD"
const DMRD_HEADER_LEN = 20; // magic(4) + seq(1) + srcId(3) + dstId(3) + repeaterId(4) + flags(1) + streamId(4)
const MEDIA_STRIPPED = 'media-stripped';

export function sanitizeDmr(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  policy: SanitizationPolicy,
  intents?: IntentCollector,
  packetIndex = 0,
): AppLayerResult | null {
  if (length < DMRD_HEADER_LEN) return null;
  for (let i = 0; i < DMRD_MAGIC.length; i++) {
    if (buffer[offset + i] !== DMRD_MAGIC[i]) return null;
  }

  patchRadioId(buffer, offset + 5, collector, mapping); // srcId (3 bytes BE)
  patchRadioId(buffer, offset + 8, collector, mapping); // dstId (3 bytes BE)

  const coverage: AppLayerResult['coverage'] = [
    { protocol: 'dmr', offset, length: DMRD_HEADER_LEN, status: 'covered' },
  ];
  const issues: string[] = [];
  const voiceOff = offset + DMRD_HEADER_LEN;
  const voiceLen = length - DMRD_HEADER_LEN;

  if (voiceLen > 0) {
    if (policy.mediaPolicy === 'drop' || policy.preset === 'high-privacy') {
      // High privacy: truncate after header via export boundary (unsupported prefix end).
      coverage.push({
        protocol: 'dmr-voice',
        offset: voiceOff,
        length: voiceLen,
        status: 'unsupported',
      });
      issues.push(MEDIA_STRIPPED);
    } else {
      // Diagnostic strip-payload (and any non-drop policy): length-preserving mask.
      // T68 — never emit preserved-unsafe for AMBE on fixed levels.
      const fill = createMaskFill({
        length: voiceLen,
        packetIndex,
        offset: voiceOff,
        domain: MEDIA_STRIPPED,
      });
      collector.maskRange(voiceOff, fill);
      intents?.recordMaskRange(packetIndex, voiceOff, voiceLen, MEDIA_STRIPPED, 'dmr-voice');
      coverage.push({
        protocol: 'dmr-voice',
        offset: voiceOff,
        length: voiceLen,
        status: 'redacted',
      });
      issues.push(MEDIA_STRIPPED);
    }
  }

  return { coverage, issues };
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
