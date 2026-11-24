/**
 * DATA frame wire directory — header scan only (no payload copy).
 * Enables selective packet restore without walking the whole file twice.
 */

import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import {
  RECOVERY_FOOTER_BYTES,
  RECOVERY_FRAME_HEADER_BYTES,
  RECOVERY_FRAME_TYPE_DATA,
  RECOVERY_FRAME_TYPE_INDEX,
  recoveryFrameWireSize,
} from '../codec/formatConstants'
import { parseFrameHeader } from '../codec/frameCodec'
import { readBlobSlice } from './recoveryBundleReader'

export interface DataFrameLocation {
  readonly frameIndex: number
  readonly fileOffset: number
  readonly wireBytes: number
  readonly plaintextLength: number
}

/**
 * Scan DATA frames from after preamble until INDEX directory / FINAL.
 * Stops at footer.indexDirectoryOffset when provided (preferred).
 */
export async function buildDataFrameDirectory(input: {
  recoveryBlob: Blob
  preambleHeaderLength: number
  /** Absolute offset where INDEX frames start (from footer). */
  indexDirectoryOffset: number
  expectedDataFrameCount?: number
}): Promise<PcapRecoveryResult<readonly DataFrameLocation[]>> {
  const end = Math.min(input.indexDirectoryOffset, input.recoveryBlob.size - RECOVERY_FOOTER_BYTES)
  if (end < input.preambleHeaderLength) {
    return recoveryFail(PCAP_RECOVERY_ERROR.frameOrder, 'invalid DATA region')
  }

  const out: DataFrameLocation[] = []
  let offset = input.preambleHeaderLength

  while (offset < end) {
    if (out.length > PCAP_RECOVERY_LIMITS.maxDataFrames) {
      return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many DATA frames')
    }
    const headerPeek = await readBlobSlice(input.recoveryBlob, offset, RECOVERY_FRAME_HEADER_BYTES)
    if (!headerPeek.ok) return headerPeek
    const parsed = parseFrameHeader(headerPeek.value, 0)
    if (!parsed.ok) return parsed

    if (parsed.value.frameType === RECOVERY_FRAME_TYPE_INDEX) {
      break
    }
    if (parsed.value.frameType !== RECOVERY_FRAME_TYPE_DATA) {
      return recoveryFail(PCAP_RECOVERY_ERROR.frameOrder, 'unexpected non-DATA before INDEX')
    }

    const wireBytes = recoveryFrameWireSize(parsed.value.payloadLength)
    if (offset + wireBytes > end) {
      return recoveryFail(PCAP_RECOVERY_ERROR.frameMissing, 'truncated DATA frame')
    }
    out.push({
      frameIndex: parsed.value.frameIndex,
      fileOffset: offset,
      wireBytes,
      plaintextLength: parsed.value.plaintextLength,
    })
    offset += wireBytes
  }

  if (
    input.expectedDataFrameCount !== undefined
    && out.length !== input.expectedDataFrameCount
  ) {
    return recoveryFail(PCAP_RECOVERY_ERROR.frameMissing, 'DATA frame count mismatch')
  }

  return recoveryOk(out)
}
