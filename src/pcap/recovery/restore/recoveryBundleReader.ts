/**
 * Bounded recovery bundle reader — Blob.slice only; never full-file arrayBuffer.
 */

import { bytesEqual, bytesToHex } from '../../../crypto/incrementalSha256'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import { parseFooter, type RecoveryFooter } from '../codec/footerCodec'
import { parsePreamble, type RecoveryPreamble } from '../codec/preambleCodec'
import {
  RECOVERY_FOOTER_BYTES,
  RECOVERY_FRAME_HEADER_BYTES,
  RECOVERY_MAGIC_ASCII,
  RECOVERY_PREAMBLE_LENGTH,
} from '../codec/formatConstants'
import { parseFrame } from '../codec/frameCodec'

export async function readBlobSlice(
  blob: Blob,
  offset: number,
  length: number,
): Promise<PcapRecoveryResult<Uint8Array>> {
  if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(length) || length < 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'invalid slice')
  }
  if (offset + length > blob.size) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'slice out of range')
  }
  if (length > PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes + RECOVERY_FRAME_HEADER_BYTES + 64) {
    // Allow frame-sized reads; reject absurd slices early.
    if (length > 4 * PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes) {
      return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'slice exceeds limit')
    }
  }
  const ab = await blob.slice(offset, offset + length).arrayBuffer()
  return recoveryOk(new Uint8Array(ab))
}

export async function peekRecoveryMagic(blob: Blob): Promise<PcapRecoveryResult<boolean>> {
  if (blob.size < 8) return recoveryOk(false)
  const head = await readBlobSlice(blob, 0, 8)
  if (!head.ok) return head
  return recoveryOk(new TextDecoder().decode(head.value) === RECOVERY_MAGIC_ASCII)
}

export async function readRecoveryFooter(blob: Blob): Promise<PcapRecoveryResult<RecoveryFooter>> {
  if (blob.size < RECOVERY_FOOTER_BYTES) {
    return recoveryFail(PCAP_RECOVERY_ERROR.footerInvalid, 'bundle too short')
  }
  if (blob.size > PCAP_RECOVERY_LIMITS.maxBundleImportBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'bundle exceeds import limit')
  }
  const bytes = await readBlobSlice(blob, blob.size - RECOVERY_FOOTER_BYTES, RECOVERY_FOOTER_BYTES)
  if (!bytes.ok) return bytes
  const footer = parseFooter(bytes.value)
  if (!footer.ok) return footer
  if (Number(footer.value.totalByteLength) !== blob.size) {
    return recoveryFail(PCAP_RECOVERY_ERROR.footerInvalid, 'footer total length mismatch')
  }
  return footer
}

export async function readRecoveryPreamble(blob: Blob): Promise<PcapRecoveryResult<RecoveryPreamble>> {
  if (blob.size < RECOVERY_PREAMBLE_LENGTH) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'bundle too short')
  }
  // Peek fixed header to learn headerLength without reading the whole file.
  const peekLen = Math.min(blob.size, PCAP_RECOVERY_LIMITS.maxPreambleBytes)
  const peek = await readBlobSlice(blob, 0, peekLen)
  if (!peek.ok) return peek
  return parsePreamble(peek.value)
}

export interface RecoveryBundleBounds {
  readonly preamble: RecoveryPreamble
  readonly footer: RecoveryFooter
  readonly anonymizedHashPrefixHex: string
}

/**
 * Load preamble + footer only and cross-check recoveryId / hash prefix.
 */
export async function openRecoveryBundleBounds(
  recoveryBlob: Blob,
): Promise<PcapRecoveryResult<RecoveryBundleBounds>> {
  const isRecovery = await peekRecoveryMagic(recoveryBlob)
  if (!isRecovery.ok) return isRecovery
  if (!isRecovery.value) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'not a recovery bundle')
  }
  const preamble = await readRecoveryPreamble(recoveryBlob)
  if (!preamble.ok) return preamble
  const footer = await readRecoveryFooter(recoveryBlob)
  if (!footer.ok) return footer

  if (!bytesEqual(preamble.value.recoveryId, footer.value.recoveryId)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.pairMismatch, 'recoveryId mismatch')
  }
  if (!bytesEqual(preamble.value.anonymizedSha256Prefix64, footer.value.anonymizedSha256Prefix64)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.pairMismatch, 'hash prefix mismatch')
  }

  return recoveryOk({
    preamble: preamble.value,
    footer: footer.value,
    anonymizedHashPrefixHex: bytesToHex(preamble.value.anonymizedSha256Prefix64),
  })
}

/** Read a single frame at absolute file offset (header + plaintext payload). */
export async function readFullFrameAt(
  blob: Blob,
  offset: number,
): Promise<PcapRecoveryResult<{ frameBytes: Uint8Array; wireBytes: number }>> {
  const headerPeek = await readBlobSlice(blob, offset, RECOVERY_FRAME_HEADER_BYTES)
  if (!headerPeek.ok) return headerPeek
  const view = new DataView(
    headerPeek.value.buffer,
    headerPeek.value.byteOffset,
    headerPeek.value.byteLength,
  )
  const plaintextLength = view.getUint32(8, true)
  const payloadLength = view.getUint32(12, true)
  if (plaintextLength > PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'frame plaintext exceeds limit')
  }
  if (payloadLength !== plaintextLength || payloadLength > PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'frame payload exceeds limit')
  }
  const wireBytes = RECOVERY_FRAME_HEADER_BYTES + payloadLength
  const frameBytes = await readBlobSlice(blob, offset, wireBytes)
  if (!frameBytes.ok) return frameBytes
  const parsed = parseFrame(frameBytes.value, 0)
  if (!parsed.ok) return parsed
  return recoveryOk({ frameBytes: frameBytes.value, wireBytes })
}
