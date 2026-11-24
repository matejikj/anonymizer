/**
 * Full byte-for-byte restore — stream DATA frames, verify length + SHA-256 (step 8).
 * Never publishes a partial Blob as the original on mismatch/auth/cancel.
 */

import {
  bytesEqual,
  bytesToHex,
  IncrementalSha256,
} from '../../../crypto/incrementalSha256'
import { wipeBytes } from '../../../crypto/wipe'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import type { PcapRecoveryManifestV1, RestoreSummary } from '../domain/types'
import type { RecoveryBundleBounds } from './recoveryBundleReader'
import { buildDataFrameDirectory } from './dataFrameDirectory'
import { decryptDataFrameAt, type DecryptedFrameCache } from './dataFrameDecrypt'
import { applyRestoreOpsToRange, parseRestoreOpsFrame } from '../codec/literalFrameCodec'

export interface FullRestoreStreamHandlers {
  onChunk: (chunk: ArrayBuffer, chunkIndex: number) => Promise<void>
  onProgress?: (done: number, total: number) => void
  isCancelled?: () => boolean
}

/**
 * Stream all DATA plaintext in order. Caller buffers chunks privately until
 * the returned summary has verified === true; on failure discard buffers.
 */
export async function streamFullRestore(input: {
  recoveryBlob: Blob
  bounds: RecoveryBundleBounds
  manifest: PcapRecoveryManifestV1
  cache?: DecryptedFrameCache
  anonymizedBlob?: Blob | null
  handlers: FullRestoreStreamHandlers
}): Promise<PcapRecoveryResult<RestoreSummary>> {
  const expectedLen = Number(input.manifest.originalByteLength)
  if (!Number.isSafeInteger(expectedLen) || expectedLen < 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'invalid original length')
  }
  if (expectedLen > PCAP_RECOVERY_LIMITS.maxBundleImportBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'original exceeds restore limit')
  }

  const dir = await buildDataFrameDirectory({
    recoveryBlob: input.recoveryBlob,
    preambleHeaderLength: input.bounds.preamble.headerLength,
    indexDirectoryOffset: Number(input.bounds.footer.indexDirectoryOffset),
    expectedDataFrameCount: input.manifest.dataFrameCount,
  })
  if (!dir.ok) return dir

  const hasher = new IncrementalSha256()
  let written = 0
  let chunkIndex = 0
  let lastProgress = 0
  const copyAnon = input.manifest.restoreEncoding === 'copy-anonymized-literal-v1'
  if (copyAnon && !input.anonymizedBlob) {
    return recoveryFail(PCAP_RECOVERY_ERROR.pairMismatch, 'COPY_ANON restore requires anonymized file')
  }

  try {
    for (const loc of dir.value) {
      if (input.handlers.isCancelled?.()) {
        return recoveryFail(PCAP_RECOVERY_ERROR.cancelled, 'cancelled')
      }
      const plain = await decryptDataFrameAt({
        recoveryBlob: input.recoveryBlob,
        loc,
        cache: input.cache,
      })
      if (!plain.ok) return plain

      let restored = plain.value
      if (copyAnon) {
        const parsed = parseRestoreOpsFrame(plain.value)
        if (!parsed.ok) {
          if (!input.cache) wipeBytes(plain.value)
          return parsed
        }
        const ops = parsed.value
        if (ops.length === 0) {
          if (!input.cache) wipeBytes(plain.value)
          continue
        }
        const start = ops[0]!.originalOffset
        const last = ops[ops.length - 1]!
        const end = last.originalOffset + last.length
        if (start !== written) {
          if (!input.cache) wipeBytes(plain.value)
          return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'COPY_ANON frames are not contiguous')
        }
        restored = new Uint8Array(end - start)
        const applied = await applyRestoreOpsToRange({
          ops,
          rangeStart: start,
          rangeEnd: end,
          anonymized: input.anonymizedBlob!,
          out: restored,
        })
        if (!applied.ok) {
          if (!input.cache) wipeBytes(plain.value)
          wipeBytes(restored)
          return applied
        }
        if (!input.cache) wipeBytes(plain.value)
      }

      if (written + restored.byteLength > expectedLen) {
        if (copyAnon || !input.cache) wipeBytes(restored)
        return recoveryFail(PCAP_RECOVERY_ERROR.outputLengthMismatch, 'output exceeds expected length')
      }

      hasher.update(restored)
      const ab = restored.buffer.slice(
        restored.byteOffset,
        restored.byteOffset + restored.byteLength,
      ) as ArrayBuffer
      const cached = input.cache?.get(loc.frameIndex)
      await input.handlers.onChunk(ab, chunkIndex)
      chunkIndex += 1
      written += restored.byteLength
      if (copyAnon || !cached) wipeBytes(restored)

      const now = Date.now()
      if (now - lastProgress >= 100 || written === expectedLen) {
        lastProgress = now
        input.handlers.onProgress?.(written, expectedLen)
      }
    }

    if (written !== expectedLen) {
      return recoveryFail(
        PCAP_RECOVERY_ERROR.outputLengthMismatch,
        'restored length does not match manifest',
      )
    }

    const digest = hasher.digest()
    if (!bytesEqual(digest, input.manifest.originalSha256)) {
      return recoveryFail(
        PCAP_RECOVERY_ERROR.outputHashMismatch,
        'restored SHA-256 does not match manifest',
      )
    }

    return recoveryOk({
      kind: 'full',
      fileName: input.manifest.originalFileName || 'capture.restored.pcap',
      byteLength: written,
      sha256Hex: bytesToHex(digest),
      verified: true,
    })
  } catch (err) {
    return recoveryFail(
      PCAP_RECOVERY_ERROR.internal,
      err instanceof Error ? err.message : 'full restore failed',
    )
  }
}
