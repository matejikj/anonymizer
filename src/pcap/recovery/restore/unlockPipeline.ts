/**
 * Open pipeline — read FINAL + INDEX plaintext frames; footer binding; no DATA read yet.
 */

import { bytesEqual, bytesToHex } from '../../../crypto/incrementalSha256'
import { wipeBytes } from '../../../crypto/wipe'
import {
  PCAP_RECOVERY_ERROR,
  recoveryAuthFailed,
  recoveryFail,
  recoveryOk,
  type PcapRecoveryResult,
} from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import type { PcapRecoveryManifestV1, UnlockedRecoverySummary } from '../domain/types'
import { compactIndexSha256, joinCompactIndexFrames } from '../codec/compactIndexCodec'
import { footerSha256 } from '../codec/footerCodec'
import { parseFrame } from '../codec/frameCodec'
import {
  RECOVERY_FRAME_TYPE_FINAL,
  RECOVERY_FRAME_TYPE_INDEX,
} from '../codec/formatConstants'
import { parseManifest } from '../codec/manifestCodec'
import { readFullFrameAt } from './recoveryBundleReader'
import type { RecoveryBundleBounds } from './recoveryBundleReader'
import { buildUnlockedLookupIndex, type UnlockedLookupIndex } from './unlockedLookupIndex'

export interface UnlockResult {
  readonly manifest: PcapRecoveryManifestV1
  readonly index: UnlockedLookupIndex
  readonly summary: Omit<UnlockedRecoverySummary, 'sessionId' | 'generationId'>
}

/**
 * Verify FINAL, footer binding, and all INDEX frames; build lookup index.
 * Tamper / pair mismatch → same public authFailed code.
 */
export async function unlockRecoveryPair(input: {
  recoveryBlob: Blob
  bounds: RecoveryBundleBounds
  anonymizedSha256: Uint8Array
  isCancelled?: () => boolean
}): Promise<PcapRecoveryResult<UnlockResult>> {
  if (input.isCancelled?.()) {
    return recoveryFail(PCAP_RECOVERY_ERROR.cancelled, 'cancelled')
  }

  const footer = input.bounds.footer
  const finalOffset = Number(footer.finalFrameOffset)
  const finalLen = Number(footer.finalFrameLength)
  if (!Number.isSafeInteger(finalOffset) || !Number.isSafeInteger(finalLen) || finalLen <= 0) {
    return recoveryAuthFailed()
  }

  const finalFrame = await readFullFrameAt(input.recoveryBlob, finalOffset)
  if (!finalFrame.ok) return recoveryAuthFailed()
  if (finalFrame.value.wireBytes !== finalLen) {
    wipeBytes(finalFrame.value.frameBytes)
    return recoveryAuthFailed()
  }

  const finalHeader = parseFrame(finalFrame.value.frameBytes, 0)
  if (!finalHeader.ok || finalHeader.value.frameType !== RECOVERY_FRAME_TYPE_FINAL) {
    wipeBytes(finalFrame.value.frameBytes)
    return recoveryAuthFailed()
  }

  const manifestPlain = finalHeader.value.payload.slice()
  wipeBytes(finalFrame.value.frameBytes)

  const manifestParsed = parseManifest(manifestPlain)
  wipeBytes(manifestPlain)
  if (!manifestParsed.ok) return recoveryAuthFailed()
  const manifest = manifestParsed.value

  const expectedFooterHash = footerSha256(footer.bytes)
  if (!bytesEqual(manifest.footerSha256, expectedFooterHash)) {
    return recoveryAuthFailed()
  }
  if (!bytesEqual(manifest.anonymizedSha256, input.anonymizedSha256)) {
    return recoveryAuthFailed()
  }
  if (!bytesEqual(manifest.recoveryId, input.bounds.preamble.recoveryId)) {
    return recoveryAuthFailed()
  }
  if (manifest.indexFrameCount !== footer.indexFrameCount) {
    return recoveryAuthFailed()
  }

  const indexParts: Uint8Array[] = []
  let offset = Number(footer.indexDirectoryOffset)
  const indexEnd = offset + Number(footer.indexDirectoryLength)
  if (
    !Number.isSafeInteger(offset)
    || !Number.isSafeInteger(indexEnd)
    || offset < 0
    || indexEnd > input.recoveryBlob.size
  ) {
    return recoveryAuthFailed()
  }

  let frames = 0
  while (offset < indexEnd && frames < footer.indexFrameCount) {
    if (input.isCancelled?.()) {
      for (const p of indexParts) wipeBytes(p)
      return recoveryFail(PCAP_RECOVERY_ERROR.cancelled, 'cancelled')
    }
    const frame = await readFullFrameAt(input.recoveryBlob, offset)
    if (!frame.ok) {
      for (const p of indexParts) wipeBytes(p)
      return recoveryAuthFailed()
    }
    const header = parseFrame(frame.value.frameBytes, 0)
    if (!header.ok || header.value.frameType !== RECOVERY_FRAME_TYPE_INDEX) {
      wipeBytes(frame.value.frameBytes)
      for (const p of indexParts) wipeBytes(p)
      return recoveryAuthFailed()
    }
    indexParts.push(header.value.payload.slice())
    wipeBytes(frame.value.frameBytes)
    offset += frame.value.wireBytes
    frames += 1
  }

  if (frames !== footer.indexFrameCount) {
    for (const p of indexParts) wipeBytes(p)
    return recoveryAuthFailed()
  }

  const joined = joinCompactIndexFrames(indexParts)
  for (const p of indexParts) wipeBytes(p)
  const indexHash = compactIndexSha256(joined)
  if (!bytesEqual(indexHash, manifest.indexSha256)) {
    wipeBytes(joined)
    return recoveryAuthFailed()
  }

  const index = buildUnlockedLookupIndex(joined)
  wipeBytes(joined)
  if (!index.ok) return recoveryAuthFailed()

  const policyHash = new TextDecoder().decode(manifest.policyHash)

  return recoveryOk({
    manifest,
    index: index.value,
    summary: {
      pcapLevel: manifest.pcapLevel,
      policyHash,
      engineVersion: manifest.engineVersion,
      originalFormat: manifest.originalFormat,
      originalByteLength: Number(manifest.originalByteLength),
      anonymizedByteLength: Number(manifest.anonymizedByteLength),
      lookupEntryCount: index.value.entryCount,
      originalPacketCount: Number(manifest.originalPacketCount),
      anonymizedPacketCount: Number(manifest.anonymizedPacketCount),
      idleTimeoutMs: PCAP_RECOVERY_LIMITS.sessionIdleTimeoutMs,
    },
  })
}

export function policyHashHex(bytes: Uint8Array): string {
  return bytesToHex(bytes)
}
