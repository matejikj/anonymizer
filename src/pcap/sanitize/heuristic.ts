/**
 * Generic best-effort payload scanner — the last fallback in the app-layer dispatch
 * chain, after every structural decoder (DNS/DHCP/SIP/TLS/HTTP) has declined.
 *
 * T69 — printable text payloads go through free-text allowlist sanitization.
 * Empty/binary payloads still return empty coverage so the caller can mark
 * `unsupported` (CF-03).
 */

import type { PatchCollector } from './PatchCollector';
import type { MappingLike } from '../anonymization/mapping';
import type { AppLayerResult } from './types';
import type { IntentCollector } from '../discovery/intentCollector';
import { sanitizeTextPayload } from '../protocols/application/textproto/index.ts';

const GENERIC_SCAN_LIMIT = 65536;

const MIN_PRINTABLE_RATIO = 0.85;

function isPrintableAsciiByte(b: number): boolean {
  return b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b <= 0x7e);
}

/** Skip non-text payloads — binary proprietary traffic stays unsupported for T74. */
function looksLikeText(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length === 0) return false;
  let printable = 0;
  for (let i = 0; i < length; i++) {
    if (isPrintableAsciiByte(buffer[offset + i]!)) printable += 1;
  }
  return printable / length >= MIN_PRINTABLE_RATIO;
}

export function sanitizeGenericPayload(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
  highPrivacy = false,
): AppLayerResult {
  const scanLen = Math.min(length, GENERIC_SCAN_LIMIT);

  // CF-03: empty coverage is the correct "found nothing" signal for binary payloads.
  if (!looksLikeText(buffer, offset, scanLen)) {
    return { coverage: [] };
  }

  const r = sanitizeTextPayload({
    buffer,
    absoluteOffset: offset,
    byteLength: scanLen,
    collector,
    mapping,
    intents,
    packetIndex,
    highPrivacy,
    protocolId: 'heuristic',
  });

  return { coverage: [{ protocol: 'heuristic', offset, length: scanLen, status: r.coverageStatus }] };
}
