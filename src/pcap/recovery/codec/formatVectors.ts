/**
 * Manually verifiable v4 format vectors.
 * Used by contract tests; codecs must stay bit-compatible.
 */

import {
  RECOVERY_FORMAT_VERSION,
  RECOVERY_FRAME_FLAG_NONE,
  RECOVERY_FRAME_HEADER_BYTES,
  RECOVERY_FRAME_TYPE_DATA,
  RECOVERY_FRAME_TYPE_FINAL,
  RECOVERY_FRAME_TYPE_INDEX,
  RECOVERY_FOOTER_BYTES,
  RECOVERY_MAGIC_ASCII,
  RECOVERY_MAGIC_BYTES,
  RECOVERY_MANDATORY_FLAGS_NONE,
  RECOVERY_OPTIONAL_FLAGS_NONE,
  RECOVERY_PREAMBLE_LENGTH,
  RECOVERY_SCHEMA_VERSION,
  recoveryFrameWireSize,
} from './formatConstants'

/** Empty / zeroed fields — useful for layout offset checks. */
export const RECOVERY_FORMAT_VECTOR_EMPTY = {
  magicAscii: RECOVERY_MAGIC_ASCII,
  magicHex: bytesToHex(RECOVERY_MAGIC_BYTES),
  formatVersion: RECOVERY_FORMAT_VERSION,
  schemaVersion: RECOVERY_SCHEMA_VERSION,
  preambleLength: RECOVERY_PREAMBLE_LENGTH,
  footerLength: RECOVERY_FOOTER_BYTES,
  frameHeaderLength: RECOVERY_FRAME_HEADER_BYTES,
  mandatoryFlags: RECOVERY_MANDATORY_FLAGS_NONE,
  optionalFlags: RECOVERY_OPTIONAL_FLAGS_NONE,
} as const

/**
 * Hand-assembled minimal preamble with deterministic ids.
 * Not a valid full bundle — only layout + LE encoding.
 */
export function buildPreambleLayoutVector(): Uint8Array {
  const headerLength = RECOVERY_PREAMBLE_LENGTH
  const out = new Uint8Array(headerLength)
  const view = new DataView(out.buffer)

  out.set(RECOVERY_MAGIC_BYTES, 0)
  view.setUint16(8, RECOVERY_FORMAT_VERSION, true)
  view.setUint16(10, RECOVERY_SCHEMA_VERSION, true)
  view.setUint16(12, headerLength, true)
  view.setUint16(14, RECOVERY_MANDATORY_FLAGS_NONE, true)
  view.setUint16(16, RECOVERY_OPTIONAL_FLAGS_NONE, true)
  view.setUint16(18, 0, true)

  for (let i = 0; i < 16; i++) out[20 + i] = i
  for (let i = 0; i < 8; i++) out[36 + i] = 0xc0 + i

  return out
}

/** Minimal DATA frame header claiming 0-byte plaintext. */
export function buildEmptyDataFrameHeaderVector(frameIndex = 0): Uint8Array {
  const out = new Uint8Array(RECOVERY_FRAME_HEADER_BYTES)
  const view = new DataView(out.buffer)
  out[0] = RECOVERY_FRAME_TYPE_DATA
  out[1] = RECOVERY_FRAME_FLAG_NONE
  view.setUint16(2, 0, true)
  view.setUint32(4, frameIndex, true)
  view.setUint32(8, 0, true)
  view.setUint32(12, 0, true)
  return out
}

export const RECOVERY_FRAME_TYPE_VECTORS = {
  data: RECOVERY_FRAME_TYPE_DATA,
  index: RECOVERY_FRAME_TYPE_INDEX,
  final: RECOVERY_FRAME_TYPE_FINAL,
  emptyDataWireSize: recoveryFrameWireSize(0),
} as const

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}
