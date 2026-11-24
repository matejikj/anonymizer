/**
 * Recovery bundle writer — PREAMBLE → plaintext DATA → INDEX → FINAL → FOOTER.
 * DATA is full-literal by default; COPY_ANON is opt-in and falls back on uncertainty.
 */

import { IncrementalSha256, sha256 } from '../../../crypto/incrementalSha256'
import { randomBytes } from '../../../crypto/randomBytes'
import { wipeBytes } from '../../../crypto/wipe'
import { CaptureFormat } from '../../domain/types'
import type { PacketRecordDescriptor } from '../../domain/types'
import type { PcapPlanSnapshot } from '../../export/planSnapshot'
import { CancellationError } from '../../capture/cancellation'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryErrorCode, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import {
  assertRecoveryExportAllowed,
  planIdentityFromSnapshot,
} from '../domain/planIdentity'
import type { PcapRecoveryManifestV1, PcapRecoveryRestoreEncoding, RecoveryExportOptions } from '../domain/types'
import { writeFooter, footerSha256 } from '../codec/footerCodec'
import { writeManifest, parseManifest } from '../codec/manifestCodec'
import { writePreamble, parsePreamble } from '../codec/preambleCodec'
import {
  RECOVERY_FOOTER_BYTES,
  RECOVERY_FRAME_TYPE_DATA,
  RECOVERY_FRAME_TYPE_FINAL,
  RECOVERY_FRAME_TYPE_INDEX,
  recoveryFrameWireSize,
} from '../codec/formatConstants'
import { parseFrame, writeFrameEnvelope } from '../codec/frameCodec'
import {
  applyRestoreOpsToRange,
  parseRestoreOpsFrame,
} from '../codec/literalFrameCodec'
import {
  compactIndexSha256,
  joinCompactIndexFrames,
  parseCompactIndex,
  splitCompactIndexFrames,
  type CompactIndexView,
} from '../codec/compactIndexCodec'
import {
  readSourceLiteralPieces,
  type SourceFrameReaderResult,
  type SourceRangeEntry,
} from './sourceFrameReader'
import { emitCopyAnonDataFrames } from './copyAnonPlanner'
import type { ProvenanceCopyRun } from '../../export/anonymizedProvenance'
import { buildCompactIndexFromSeed, buildEmptyCompactIndex } from './compactIndexBuilder'

export interface RecoveryBundleWriteProgress {
  readonly phase: 'writing-recovery'
  readonly bytesDone: number
  readonly bytesTotal: number
  readonly framesEmitted: number
}

export interface RecoveryBundleWriteResult {
  readonly recoveryId: Uint8Array
  readonly originalSha256: Uint8Array
  readonly originalByteLength: number
  readonly anonymizedSha256: Uint8Array
  readonly anonymizedByteLength: number
  readonly dataFrameCount: number
  readonly indexFrameCount: number
  readonly lookupEntryCount: number
  readonly occurrenceCount: number
  readonly indexSha256: Uint8Array
  readonly chunkCount: number
  readonly rangeDirectory: readonly SourceRangeEntry[]
  readonly source: SourceFrameReaderResult
  readonly restoreEncoding: PcapRecoveryRestoreEncoding
}

/**
 * Write a full-literal recovery sidecar, streaming plaintext frames via onChunk.
 * Requires completed anonymized SHA-256 (writer finishes anonymized stream first).
 */
export async function writeFullLiteralRecoveryBundle(input: {
  sourceBlob: Blob
  descriptors: readonly PacketRecordDescriptor[]
  plan: PcapPlanSnapshot
  anonymizedSha256: Uint8Array
  anonymizedByteLength: number
  /** Compact transferable seed; wiped after INDEX build. Omit for empty INDEX. */
  indexSeed?: ArrayBuffer
  isCancelled?: () => boolean
  onChunk: (buffer: ArrayBuffer, chunkIndex: number) => void | Promise<void>
  onProgress?: (p: RecoveryBundleWriteProgress) => void
  maxPlaintextBytes?: number
  /**
   * Opt-in COPY_ANON. Ignored unless provenanceCopies are valid and save bytes;
   * otherwise the writer falls back to full-literal.
   */
  copyAnon?: boolean
  provenanceCopies?: readonly ProvenanceCopyRun[]
}): Promise<PcapRecoveryResult<RecoveryBundleWriteResult>> {
  const allowed = assertRecoveryExportAllowed(input.plan, { enabled: true })
  if (!allowed.ok) return allowed
  if (input.anonymizedSha256.byteLength !== PCAP_RECOVERY_LIMITS.sha256Bytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'anonymized sha256 must be 32 bytes')
  }

  const identity = planIdentityFromSnapshot(input.plan)
  const recoveryId = randomBytes(PCAP_RECOVERY_LIMITS.recoveryIdBytes)
  const hashPrefix = input.anonymizedSha256.subarray(0, PCAP_RECOVERY_LIMITS.anonymizedHashPrefixBytes)

  const preamble = writePreamble({
    recoveryId,
    anonymizedSha256Prefix64: hashPrefix,
  })
  if (!preamble.ok) return preamble

  const sealFrame = (
    frameType: typeof RECOVERY_FRAME_TYPE_DATA | typeof RECOVERY_FRAME_TYPE_INDEX | typeof RECOVERY_FRAME_TYPE_FINAL,
    frameIndex: number,
    plaintext: Uint8Array,
  ): PcapRecoveryResult<Uint8Array> =>
    writeFrameEnvelope({
      frameType,
      frameIndex,
      plaintext,
    })

  let chunkIndex = 0
  let wireOffset = 0
  let framesEmitted = 0
  let lastProgressAt = 0

  const emit = async (bytes: Uint8Array) => {
    if (input.isCancelled?.()) throw new CancellationError('Recovery export cancelled')
    const copy = bytes.slice()
    await input.onChunk(copy.buffer, chunkIndex)
    chunkIndex += 1
    wireOffset += bytes.byteLength
  }

  const maybeProgress = (bytesDone: number, bytesTotal: number) => {
    const now = Date.now()
    if (now - lastProgressAt < 100 && bytesDone < bytesTotal) return
    lastProgressAt = now
    input.onProgress?.({
      phase: 'writing-recovery',
      bytesDone,
      bytesTotal,
      framesEmitted,
    })
  }

  await emit(preamble.value)

  let frameIndex = 0

  try {
    const emitDataFrame = async (plaintext: Uint8Array, originalEndHint: number) => {
      const framed = sealFrame(RECOVERY_FRAME_TYPE_DATA, frameIndex, plaintext)
      wipeBytes(plaintext)
      if (!framed.ok) {
        throw new RecoveryWriteError(framed.code, framed.message)
      }
      await emit(framed.value)
      frameIndex += 1
      framesEmitted += 1
      maybeProgress(Math.min(originalEndHint, input.sourceBlob.size), input.sourceBlob.size)
    }

    let restoreEncoding: PcapRecoveryRestoreEncoding = 'full-literal-frames-v1'
    const tryCopyAnon =
      input.copyAnon === true
      && (input.provenanceCopies?.length ?? 0) > 0

    let sourceResult: PcapRecoveryResult<SourceFrameReaderResult>
    if (tryCopyAnon) {
      sourceResult = await emitCopyAnonDataFrames({
        sourceBlob: input.sourceBlob,
        descriptors: input.descriptors,
        copies: input.provenanceCopies!,
        anonymizedByteLength: input.anonymizedByteLength,
        maxPlaintextBytes: input.maxPlaintextBytes,
        isCancelled: input.isCancelled,
        onFrame: async (frame) => {
          const end = frame.fileOffset + frame.length
          await emitDataFrame(frame.plaintext, end)
        },
      })
      if (sourceResult.ok) {
        restoreEncoding = 'copy-anonymized-literal-v1'
      } else {
        restoreEncoding = 'full-literal-frames-v1'
      }
    } else {
      sourceResult = { ok: false, code: PCAP_RECOVERY_ERROR.internal, message: 'full-literal' }
    }

    if (!sourceResult.ok) {
      if (frameIndex > 0) return sourceResult
      sourceResult = await readSourceLiteralPieces({
        sourceBlob: input.sourceBlob,
        descriptors: input.descriptors,
        maxPlaintextBytes: input.maxPlaintextBytes,
        isCancelled: input.isCancelled,
        onPiece: async (piece) => {
          const pieceEnd = piece.fileOffset + piece.bytes.byteLength
          await emitDataFrame(piece.bytes, pieceEnd)
        },
      })
    }

    if (!sourceResult.ok) return sourceResult

    const dataFrameCount = frameIndex
    const indexDirectoryOffset = wireOffset

    // --- INDEX frames ---
    let indexPlain: Uint8Array
    let lookupEntryCount = 0
    let occurrenceCount = 0

    if (input.indexSeed && input.indexSeed.byteLength > 0) {
      const built = await buildCompactIndexFromSeed({
        indexSeed: input.indexSeed,
        sourceBlob: input.sourceBlob,
        rangeDirectory: sourceResult.value.rangeDirectory,
        isCancelled: input.isCancelled,
      })
      if (!built.ok) return built
      indexPlain = built.value.plaintext
      lookupEntryCount = built.value.view.entryCount
      occurrenceCount = built.value.view.occurrenceCount
    } else {
      const empty = buildEmptyCompactIndex({
        generationId: identity.generationId,
        originalPacketCount: input.descriptors.length,
        anonymizedPacketCount:
          input.plan.packets.filter((p) => !p.drop).length || input.descriptors.length,
        rangeDirectory: sourceResult.value.rangeDirectory,
      })
      if (!empty.ok) return empty
      indexPlain = empty.value.plaintext
      lookupEntryCount = 0
      occurrenceCount = 0
    }

    const indexSha = compactIndexSha256(indexPlain)
    const indexParts = splitCompactIndexFrames(
      indexPlain,
      input.maxPlaintextBytes ?? PCAP_RECOVERY_LIMITS.defaultFramePlaintextBytes,
    ).map((p) => p.slice())
    wipeBytes(indexPlain)

    for (const part of indexParts) {
      const framed = sealFrame(RECOVERY_FRAME_TYPE_INDEX, frameIndex, part)
      wipeBytes(part)
      if (!framed.ok) {
        throw new RecoveryWriteError(framed.code, framed.message)
      }
      await emit(framed.value)
      frameIndex += 1
      framesEmitted += 1
    }

    const indexFrameCount = indexParts.length
    const indexDirectoryLength = wireOffset - indexDirectoryOffset
    const finalFrameOffset = wireOffset

    const policyHashBytes = new TextEncoder().encode(identity.policyHash)
    const originalFormat = input.plan.format === CaptureFormat.Pcapng ? 'pcapng' : 'pcap'

    const buildManifest = (footerHash: Uint8Array): PcapRecoveryManifestV1 => ({
      recoveryId,
      originalFileName: input.plan.fileName || 'capture.pcap',
      originalFormat,
      originalByteLength: BigInt(sourceResult.value.originalByteLength),
      originalSha256: sourceResult.value.originalSha256,
      anonymizedByteLength: BigInt(input.anonymizedByteLength),
      anonymizedSha256: input.anonymizedSha256,
      pcapLevel: identity.pcapLevel,
      policyHash: policyHashBytes,
      engineVersion: identity.engineVersion,
      restoreEncoding,
      lookupEncoding: 'compact-index-v1',
      dataFrameCount,
      indexFrameCount,
      lookupEntryCount: BigInt(lookupEntryCount),
      occurrenceCount: BigInt(occurrenceCount),
      originalPacketCount: BigInt(input.descriptors.length),
      anonymizedPacketCount: BigInt(
        input.plan.packets.filter((p) => !p.drop).length || input.descriptors.length,
      ),
      indexSha256: indexSha,
      footerSha256: footerHash,
    })

    const placeholderFooterHash = new Uint8Array(PCAP_RECOVERY_LIMITS.sha256Bytes)
    const manifestPlainProbe = writeManifest(buildManifest(placeholderFooterHash))
    if (!manifestPlainProbe.ok) return manifestPlainProbe
    const finalFrameLength = recoveryFrameWireSize(manifestPlainProbe.value.byteLength)
    const totalByteLength = finalFrameOffset + finalFrameLength + RECOVERY_FOOTER_BYTES

    const footer = writeFooter({
      recoveryId,
      totalByteLength,
      dataFrameCount,
      indexFrameCount,
      indexDirectoryOffset,
      indexDirectoryLength,
      finalFrameOffset,
      finalFrameLength,
      anonymizedByteLength: input.anonymizedByteLength,
      anonymizedSha256Prefix64: hashPrefix,
    })
    if (!footer.ok) return footer
    const footerHash = footerSha256(footer.value)

    const manifestPlain = writeManifest(buildManifest(footerHash))
    if (!manifestPlain.ok) return manifestPlain
    if (manifestPlain.value.byteLength !== manifestPlainProbe.value.byteLength) {
      return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'manifest length changed after footer hash')
    }
    wipeBytes(manifestPlainProbe.value)
    const finalFramed = sealFrame(RECOVERY_FRAME_TYPE_FINAL, frameIndex, manifestPlain.value)
    wipeBytes(manifestPlain.value)
    if (!finalFramed.ok) return finalFramed
    if (finalFramed.value.byteLength !== finalFrameLength) {
      return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'FINAL frame length mismatch')
    }
    await emit(finalFramed.value)
    frameIndex += 1

    await emit(footer.value)
    maybeProgress(input.sourceBlob.size, input.sourceBlob.size)

    return recoveryOk({
      recoveryId,
      originalSha256: sourceResult.value.originalSha256,
      originalByteLength: sourceResult.value.originalByteLength,
      anonymizedSha256: input.anonymizedSha256,
      anonymizedByteLength: input.anonymizedByteLength,
      dataFrameCount,
      indexFrameCount,
      lookupEntryCount,
      occurrenceCount,
      indexSha256: indexSha,
      chunkCount: chunkIndex,
      rangeDirectory: sourceResult.value.rangeDirectory,
      source: sourceResult.value,
      restoreEncoding,
    })
  } catch (err) {
    if (err instanceof RecoveryWriteError) {
      return recoveryFail(err.code, err.message)
    }
    if (err instanceof CancellationError) throw err
    return recoveryFail(
      PCAP_RECOVERY_ERROR.internal,
      err instanceof Error ? err.message : String(err),
    )
  }
}

class RecoveryWriteError extends Error {
  readonly code: PcapRecoveryErrorCode
  constructor(code: PcapRecoveryErrorCode, message: string) {
    super(message)
    this.name = 'RecoveryWriteError'
    this.code = code
  }
}

/**
 * Read DATA frames (and verify INDEX) from a recovery bundle.
 * Verify chain: parse → trusted manifest → SHA256(restored)==sourceSHA256;
 * SHA256(anon)==outputSHA256 via anonymizedSha256.
 */
export async function restoreOriginalFromDataFrames(input: {
  recoveryBytes: Uint8Array
  /** Full anonymized SHA-256 — required for pair binding. */
  anonymizedSha256: Uint8Array
  /** When false, INDEX is hash-verified then wiped without parsing. Default true. */
  verifyIndex?: boolean
  /** Required when manifest restoreEncoding is copy-anonymized-literal-v1. */
  anonymizedBytes?: Uint8Array
}): Promise<PcapRecoveryResult<{
  original: Uint8Array
  originalSha256: Uint8Array
  manifest: PcapRecoveryManifestV1
  index?: CompactIndexView
}>> {
  if (input.anonymizedSha256.byteLength !== PCAP_RECOVERY_LIMITS.sha256Bytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'anonymized sha256 must be 32 bytes')
  }
  if (input.recoveryBytes.byteLength > PCAP_RECOVERY_LIMITS.maxBundleImportBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'bundle exceeds import limit')
  }
  if (input.recoveryBytes.byteLength < RECOVERY_FOOTER_BYTES + 8) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'bundle too short')
  }

  const preamble = parsePreamble(input.recoveryBytes)
  if (!preamble.ok) return preamble

  const prefix = input.anonymizedSha256.subarray(0, PCAP_RECOVERY_LIMITS.anonymizedHashPrefixBytes)
  if (!bytesEqualPrefix(prefix, preamble.value.anonymizedSha256Prefix64)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.pairMismatch, 'anonymized hash prefix mismatch')
  }

  let offset = preamble.value.headerLength
  const end = input.recoveryBytes.byteLength - RECOVERY_FOOTER_BYTES
  const parts: Uint8Array[] = []
  const indexParts: Uint8Array[] = []
  let sawFinal = false
  let sawIndex = false
  let manifest: PcapRecoveryManifestV1 | null = null

  while (offset < end) {
    const parsedFrame = parseFrame(input.recoveryBytes, offset)
    if (!parsedFrame.ok) return parsedFrame
    const frameWire = parsedFrame.value.wireBytes
    const plain = parsedFrame.value.payload.slice()

    if (parsedFrame.value.frameType === RECOVERY_FRAME_TYPE_DATA) {
      if (sawIndex) {
        wipeBytes(plain)
        return recoveryFail(PCAP_RECOVERY_ERROR.frameOrder, 'DATA after INDEX')
      }
      parts.push(plain)
    } else if (parsedFrame.value.frameType === RECOVERY_FRAME_TYPE_INDEX) {
      sawIndex = true
      if (input.verifyIndex !== false) {
        indexParts.push(plain)
      } else {
        wipeBytes(plain)
      }
    } else if (parsedFrame.value.frameType === RECOVERY_FRAME_TYPE_FINAL) {
      const parsed = parseManifest(plain)
      wipeBytes(plain)
      if (!parsed.ok) return recoveryFail(PCAP_RECOVERY_ERROR.authFailed, parsed.message)
      manifest = parsed.value
      sawFinal = true
    } else {
      wipeBytes(plain)
      return recoveryFail(PCAP_RECOVERY_ERROR.frameOrder, 'unexpected frame type')
    }

    offset += frameWire
    if (sawFinal) break
  }

  if (!sawFinal || !manifest) {
    for (const p of parts) wipeBytes(p)
    for (const p of indexParts) wipeBytes(p)
    return recoveryFail(PCAP_RECOVERY_ERROR.frameMissing, 'FINAL frame missing')
  }

  if (!bytesEqual32(manifest.anonymizedSha256, input.anonymizedSha256)) {
    for (const p of parts) wipeBytes(p)
    for (const p of indexParts) wipeBytes(p)
    return recoveryFail(PCAP_RECOVERY_ERROR.pairMismatch, 'anonymized SHA-256 mismatch')
  }

  let indexView: CompactIndexView | undefined
  if (indexParts.length > 0) {
    const joined = joinCompactIndexFrames(indexParts)
    for (const p of indexParts) wipeBytes(p)
    const hash = compactIndexSha256(joined)
    if (!bytesEqual32(hash, manifest.indexSha256)) {
      wipeBytes(joined)
      for (const p of parts) wipeBytes(p)
      return recoveryFail(PCAP_RECOVERY_ERROR.authFailed, 'index hash mismatch')
    }
    const parsed = parseCompactIndex(joined)
    wipeBytes(joined)
    if (!parsed.ok) {
      for (const p of parts) wipeBytes(p)
      return parsed
    }
    indexView = parsed.value
  } else if (manifest.indexFrameCount > 0) {
    for (const p of parts) wipeBytes(p)
    return recoveryFail(PCAP_RECOVERY_ERROR.frameMissing, 'INDEX frames missing')
  }

  const assembled = await assembleRestoredOriginal({
    encoding: manifest.restoreEncoding,
    dataParts: parts,
    originalByteLength: Number(manifest.originalByteLength),
    anonymizedBytes: input.anonymizedBytes,
  })
  for (const p of parts) wipeBytes(p)
  if (!assembled.ok) return assembled
  if (!bytesEqual32(assembled.value.originalSha256, manifest.originalSha256)) {
    wipeBytes(assembled.value.original)
    return recoveryFail(PCAP_RECOVERY_ERROR.outputHashMismatch, 'restored SHA-256 does not match manifest')
  }
  return recoveryOk({
    original: assembled.value.original,
    originalSha256: assembled.value.originalSha256,
    manifest,
    ...(indexView ? { index: indexView } : {}),
  })
}

function bytesEqualPrefix(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  let diff = 0
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}


function bytesEqual32(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== 32 || b.byteLength !== 32) return false
  let diff = 0
  for (let i = 0; i < 32; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

async function assembleRestoredOriginal(input: {
  encoding: PcapRecoveryRestoreEncoding
  dataParts: readonly Uint8Array[]
  originalByteLength: number
  anonymizedBytes?: Uint8Array
}): Promise<PcapRecoveryResult<{ original: Uint8Array; originalSha256: Uint8Array }>> {
  const hasher = new IncrementalSha256()
  if (input.encoding === 'full-literal-frames-v1') {
    const total = input.dataParts.reduce((n, p) => n + p.byteLength, 0)
    if (total !== input.originalByteLength && Number.isSafeInteger(input.originalByteLength) && input.originalByteLength > 0) {
      // Manifest is authoritative; still concat what we have and let caller hash-gate.
    }
    const original = new Uint8Array(total)
    let o = 0
    for (const p of input.dataParts) {
      original.set(p, o)
      o += p.byteLength
    }
    hasher.update(original)
    return recoveryOk({ original, originalSha256: hasher.digest() })
  }

  if (!input.anonymizedBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.pairMismatch, 'COPY_ANON restore requires anonymized bytes')
  }
  const expected = input.originalByteLength
  if (!Number.isSafeInteger(expected) || expected < 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'invalid original length')
  }
  if (expected > PCAP_RECOVERY_LIMITS.maxBundleImportBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'original exceeds restore limit')
  }
  const original = new Uint8Array(expected)
  const filled = new Uint8Array(expected)
  for (const part of input.dataParts) {
    const parsed = parseRestoreOpsFrame(part)
    if (!parsed.ok) return parsed
    const ops = parsed.value
    if (ops.length === 0) continue
    const start = ops[0]!.originalOffset
    const last = ops[ops.length - 1]!
    const end = last.originalOffset + last.length
    if (start < 0 || end > expected || end < start) {
      return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'COPY_ANON frame coverage invalid')
    }
    const slice = new Uint8Array(end - start)
    const applied = await applyRestoreOpsToRange({
      ops,
      rangeStart: start,
      rangeEnd: end,
      anonymized: input.anonymizedBytes,
      out: slice,
    })
    if (!applied.ok) return applied
    original.set(slice, start)
    filled.fill(1, start, end)
  }
  for (let i = 0; i < filled.byteLength; i++) {
    if (filled[i] !== 1) {
      return recoveryFail(PCAP_RECOVERY_ERROR.sourceRange, 'COPY_ANON restore has gaps')
    }
  }
  hasher.update(original)
  return recoveryOk({ original, originalSha256: hasher.digest() })
}

export function recoveryOptionsFromWire(
  recovery: { enabled?: boolean; indexSeed?: ArrayBuffer; copyAnon?: boolean } | undefined,
): RecoveryExportOptions {
  if (!recovery || recovery.enabled !== true) {
    return { enabled: false }
  }
  return {
    enabled: true,
    ...(recovery.copyAnon === true ? { copyAnon: true } : {}),
  }
}

export { recoveryFrameWireSize, sha256 }
