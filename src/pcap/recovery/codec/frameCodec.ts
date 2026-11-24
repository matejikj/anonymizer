/**
 * Recovery frame envelope — v4 plaintext payloads (payloadLength == plaintextLength).
 */

import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import {
  RECOVERY_FRAME_FLAG_COMPRESSED,
  RECOVERY_FRAME_FLAG_NONE,
  RECOVERY_FRAME_HEADER_BYTES,
  RECOVERY_FRAME_TYPE_DATA,
  RECOVERY_FRAME_TYPE_FINAL,
  RECOVERY_FRAME_TYPE_INDEX,
  recoveryFrameWireSize,
} from './formatConstants'

export type RecoveryFrameType =
  | typeof RECOVERY_FRAME_TYPE_DATA
  | typeof RECOVERY_FRAME_TYPE_INDEX
  | typeof RECOVERY_FRAME_TYPE_FINAL

export interface ParsedRecoveryFrameHeader {
  readonly frameType: RecoveryFrameType
  readonly frameFlags: number
  readonly frameIndex: number
  readonly plaintextLength: number
  /** Wire payload length; for v4 equals plaintextLength. */
  readonly payloadLength: number
}

export interface ParsedRecoveryFrame extends ParsedRecoveryFrameHeader {
  /** Plaintext payload view into the source buffer. */
  readonly payload: Uint8Array
  readonly wireBytes: number
}

function isFrameType(v: number): v is RecoveryFrameType {
  return (
    v === RECOVERY_FRAME_TYPE_DATA
    || v === RECOVERY_FRAME_TYPE_INDEX
    || v === RECOVERY_FRAME_TYPE_FINAL
  )
}

export function writeFrameEnvelope(input: {
  frameType: RecoveryFrameType
  frameIndex: number
  plaintext: Uint8Array
  frameFlags?: number
}): PcapRecoveryResult<Uint8Array> {
  const flags = input.frameFlags ?? RECOVERY_FRAME_FLAG_NONE
  if (flags !== RECOVERY_FRAME_FLAG_NONE) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'unsupported frame flag')
  }
  const plaintextLength = input.plaintext.byteLength
  if (plaintextLength > PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'frame plaintext exceeds limit')
  }
  const out = new Uint8Array(recoveryFrameWireSize(plaintextLength))
  const view = new DataView(out.buffer)
  out[0] = input.frameType
  out[1] = flags
  view.setUint16(2, 0, true)
  view.setUint32(4, input.frameIndex >>> 0, true)
  view.setUint32(8, plaintextLength >>> 0, true)
  view.setUint32(12, plaintextLength >>> 0, true)
  out.set(input.plaintext, RECOVERY_FRAME_HEADER_BYTES)
  return recoveryOk(out)
}

/**
 * Parse frame header only. Does not allocate payloadLength bytes.
 */
export function parseFrameHeader(
  bytes: Uint8Array,
  offset: number,
): PcapRecoveryResult<ParsedRecoveryFrameHeader> {
  if (offset < 0 || offset + RECOVERY_FRAME_HEADER_BYTES > bytes.byteLength) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated frame header')
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const frameType = bytes[offset]!
  const frameFlags = bytes[offset + 1]!
  const reserved = view.getUint16(offset + 2, true)
  const frameIndex = view.getUint32(offset + 4, true)
  const plaintextLength = view.getUint32(offset + 8, true)
  const payloadLength = view.getUint32(offset + 12, true)

  if (reserved !== 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'reserved bytes must be zero')
  }
  if (!isFrameType(frameType)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'unknown frame type')
  }
  if ((frameFlags & RECOVERY_FRAME_FLAG_COMPRESSED) !== 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'compressed frames unsupported')
  }
  if (frameFlags !== RECOVERY_FRAME_FLAG_NONE) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'unknown frame flag')
  }
  if (plaintextLength > PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'frame plaintext exceeds limit')
  }
  if (payloadLength !== plaintextLength) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'payload length mismatch')
  }
  return recoveryOk({
    frameType,
    frameFlags,
    frameIndex,
    plaintextLength,
    payloadLength,
  })
}

export function parseFrame(
  bytes: Uint8Array,
  offset: number,
): PcapRecoveryResult<ParsedRecoveryFrame> {
  const header = parseFrameHeader(bytes, offset)
  if (!header.ok) return header
  const wireBytes = recoveryFrameWireSize(header.value.payloadLength)
  if (offset + wireBytes > bytes.byteLength) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated frame payload')
  }
  const payload = bytes.subarray(
    offset + RECOVERY_FRAME_HEADER_BYTES,
    offset + RECOVERY_FRAME_HEADER_BYTES + header.value.payloadLength,
  )
  return recoveryOk({
    ...header.value,
    payload,
    wireBytes,
  })
}

/** Track monotonic frame indices and type order: DATA* → INDEX* → FINAL. */
export class FrameSequenceTracker {
  private nextIndex = 0
  private seen = new Set<number>()
  private phase: RecoveryFrameType | 0 = 0
  private sawFinal = false
  dataCount = 0
  indexCount = 0

  accept(header: ParsedRecoveryFrameHeader): PcapRecoveryResult<void> {
    if (this.sawFinal) {
      return recoveryFail(PCAP_RECOVERY_ERROR.frameOrder, 'trailing frame after FINAL')
    }
    if (this.seen.has(header.frameIndex)) {
      return recoveryFail(PCAP_RECOVERY_ERROR.frameDuplicate, 'duplicate frame index')
    }
    if (header.frameIndex !== this.nextIndex) {
      if (header.frameIndex < this.nextIndex) {
        return recoveryFail(PCAP_RECOVERY_ERROR.frameDuplicate, 'duplicate or reordered frame')
      }
      return recoveryFail(PCAP_RECOVERY_ERROR.frameOrder, 'frame index not monotonic')
    }
    if (this.phase === 0) {
      if (header.frameType !== RECOVERY_FRAME_TYPE_DATA && header.frameType !== RECOVERY_FRAME_TYPE_FINAL) {
        return recoveryFail(PCAP_RECOVERY_ERROR.frameOrder, 'bundle must start with DATA or FINAL')
      }
      this.phase = header.frameType
    } else if (header.frameType !== this.phase) {
      if (this.phase === RECOVERY_FRAME_TYPE_DATA && header.frameType === RECOVERY_FRAME_TYPE_INDEX) {
        this.phase = RECOVERY_FRAME_TYPE_INDEX
      } else if (
        (this.phase === RECOVERY_FRAME_TYPE_DATA || this.phase === RECOVERY_FRAME_TYPE_INDEX)
        && header.frameType === RECOVERY_FRAME_TYPE_FINAL
      ) {
        this.phase = RECOVERY_FRAME_TYPE_FINAL
      } else {
        return recoveryFail(PCAP_RECOVERY_ERROR.frameOrder, 'frames reordered')
      }
    }
    if (header.frameType === RECOVERY_FRAME_TYPE_DATA) this.dataCount += 1
    if (header.frameType === RECOVERY_FRAME_TYPE_INDEX) this.indexCount += 1
    if (header.frameType === RECOVERY_FRAME_TYPE_FINAL) this.sawFinal = true
    if (this.dataCount > PCAP_RECOVERY_LIMITS.maxDataFrames) {
      return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many DATA frames')
    }
    if (this.indexCount > PCAP_RECOVERY_LIMITS.maxIndexFrames) {
      return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many INDEX frames')
    }
    this.seen.add(header.frameIndex)
    this.nextIndex += 1
    return recoveryOk(undefined)
  }

  finish(): PcapRecoveryResult<void> {
    if (!this.sawFinal) {
      return recoveryFail(PCAP_RECOVERY_ERROR.frameMissing, 'FINAL frame missing')
    }
    return recoveryOk(undefined)
  }
}
