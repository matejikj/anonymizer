/**
 * Generic best-effort payload scanner — the last fallback in the app-layer dispatch
 * chain, after every structural decoder (DNS/DHCP/SIP/TLS/HTTP) has declined.
 *
 * T63 interim (until T69 free-text allowlist / T74 light proprietary anonymization):
 * when the payload looks like text, mask the entire scanned span and report `redacted`.
 * Empty/binary payloads still return empty coverage so the caller can mark `unsupported`
 * (CF-03) — an empty scan must not claim the whole range was safely examined.
 */

import type { PatchCollector } from './PatchCollector';
import type { MappingLike } from '../anonymization/mapping';
import type { AppLayerResult } from './types';
import { createProtocolNeutralMaskFill } from './maskFill';
import type { IntentCollector } from '../discovery/intentCollector';

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
  _mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): AppLayerResult {
  const scanLen = Math.min(length, GENERIC_SCAN_LIMIT);

  // CF-03: empty coverage is the correct "found nothing" signal for binary payloads.
  if (!looksLikeText(buffer, offset, scanLen)) {
    return { coverage: [] };
  }

  // T63 — full mask until T69; status matches the mask.
  void buffer
  const fill = createProtocolNeutralMaskFill({
    length: scanLen,
    packetIndex,
    offset,
    domain: 'heuristic-interim',
  });
  try {
    collector.maskRange(offset, fill);
  } catch {
    try {
      collector.add(offset, fill);
    } catch {
      /* overlap with a prior structural patch — leave that patch */
    }
  }
  intents?.recordMaskRange(packetIndex, offset, scanLen, 'heuristic-interim', 'heuristic');

  return { coverage: [{ protocol: 'heuristic', offset, length: scanLen, status: 'redacted' }] };
}
