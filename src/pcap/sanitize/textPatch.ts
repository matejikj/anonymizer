/**
 * Shared helper for text-derived patches. `SessionMapping.map()` does not guarantee
 * its output is the same length as its input — every caller MUST use
 * `MappingLike.aliasFor()` with the wire constraint for the span being patched.
 * CF-02: replacement must match originalByteLength exactly (redaction uses padByte).
 */

import type { PatchCollector } from './PatchCollector';
import { MappingPatchError } from '../anonymization/mappingErrors';

/**
 * Compute the fixed-size patch bytes for `replacement`, exactly `originalByteLength` long.
 * Throws on length mismatch — never silently truncates or pads mapped aliases.
 * Pure (no collector access) so it can run inside a PF-06 deferred compute closure.
 */
export function computeFixedLengthAsciiBytes(
  offset: number,
  originalByteLength: number,
  replacement: string,
  padByte = 0x2d,
): Uint8Array {
  const bytes = new Uint8Array(originalByteLength);
  if (replacement.length === 0) {
    bytes.fill(padByte);
  } else if (replacement.length !== originalByteLength) {
    throw new MappingPatchError(
      'length-mismatch',
      `Text patch length ${replacement.length} !== span ${originalByteLength} at offset ${offset}`,
    );
  } else {
    for (let i = 0; i < originalByteLength; i++) {
      bytes[i] = replacement.charCodeAt(i)!;
    }
  }
  return bytes;
}

/**
 * Write `replacement` into a fixed-size patch of exactly `originalByteLength` bytes.
 * Throws on length mismatch — never silently truncates or pads mapped aliases.
 */
export function patchFixedLengthAscii(
  collector: PatchCollector,
  offset: number,
  originalByteLength: number,
  replacement: string,
  padByte = 0x2d,
): void {
  collector.add(offset, computeFixedLengthAsciiBytes(offset, originalByteLength, replacement, padByte));
}
