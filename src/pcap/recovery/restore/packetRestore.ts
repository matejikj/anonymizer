/**
 * Packet open + mini-capture restore (step 8).
 * Reads only DATA frames covering the packet span (+ file header context).
 */

import { bytesToHex, sha256 } from '../../../crypto/incrementalSha256'
import { wipeBytes } from '../../../crypto/wipe'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import type {
  PcapRecoveryManifestV1,
  RecoveryHitRef,
  RestoredPacketView,
  RestoreSummary,
} from '../domain/types'
import type { RecoveryBundleBounds } from './recoveryBundleReader'
import { buildDataFrameDirectory, type DataFrameLocation } from './dataFrameDirectory'
import {
  assembleOriginalRange,
  type DecryptedFrameCache,
} from './dataFrameDecrypt'
import type { UnlockedLookupIndex } from './unlockedLookupIndex'
import { GLOBAL_HEADER_SIZE, probeClassicPcap } from '../../capture/classicPcapFraming'
import { Endian } from '../../domain/types'

/** Soft cap so openPacket never slurps huge anonymized files for preview. */
const SAFE_ANON_PREVIEW_BYTES = 64 * 1024 * 1024

export interface PacketRestoreContext {
  recoveryBlob: Blob
  anonymizedBlob: Blob | null
  bounds: RecoveryBundleBounds
  manifest: PcapRecoveryManifestV1
  index: UnlockedLookupIndex
  cache?: DecryptedFrameCache
  dataDirectory?: readonly DataFrameLocation[] | null
}

export async function ensureDataFrameDirectory(
  ctx: PacketRestoreContext,
): Promise<PcapRecoveryResult<readonly DataFrameLocation[]>> {
  if (ctx.dataDirectory) return recoveryOk(ctx.dataDirectory)
  const built = await buildDataFrameDirectory({
    recoveryBlob: ctx.recoveryBlob,
    preambleHeaderLength: ctx.bounds.preamble.headerLength,
    indexDirectoryOffset: Number(ctx.bounds.footer.indexDirectoryOffset),
    expectedDataFrameCount: ctx.manifest.dataFrameCount,
  })
  if (!built.ok) return built
  ctx.dataDirectory = built.value
  return built
}

function resolveOriginalPacketNumber(
  index: UnlockedLookupIndex,
  hitRef: RecoveryHitRef,
): PcapRecoveryResult<number> {
  if (
    hitRef.originalPacketNumber != null
    && Number.isInteger(hitRef.originalPacketNumber)
    && hitRef.originalPacketNumber >= 1
  ) {
    return recoveryOk(hitRef.originalPacketNumber)
  }
  if (
    hitRef.anonymizedPacketNumber != null
    && Number.isInteger(hitRef.anonymizedPacketNumber)
  ) {
    const orig = index.packetMap.toOriginal(hitRef.anonymizedPacketNumber)
    if (orig != null) return recoveryOk(orig)
  }
  if (hitRef.entryIndex != null) {
    const occs = index.getOccurrences(hitRef.entryIndex)
    const occ =
      hitRef.occurrenceIndex != null
        ? occs[hitRef.occurrenceIndex]
        : occs[0]
    if (occ) return recoveryOk(occ.originalPacketNumber)
  }
  return recoveryFail(PCAP_RECOVERY_ERROR.packetNotFound, 'packet reference incomplete')
}

export function resolvePacketSpan(
  index: UnlockedLookupIndex,
  originalPacketNumber: number,
): { start: number; end: number; dataOffset: number | null } | null {
  for (let e = 0; e < index.entryCount; e++) {
    for (const occ of index.getOccurrences(e)) {
      if (occ.originalPacketNumber !== originalPacketNumber) continue
      const span = index.findSpanCovering(occ.fileOffset)
      if (span) {
        return { start: span.spanStart, end: span.spanEnd, dataOffset: occ.dataOffset }
      }
      // Packed DATA pieces may omit later source spans from the range directory.
      return { start: occ.fileOffset, end: -1, dataOffset: occ.dataOffset }
    }
  }

  const ordered = index.orderedPacketSpans()
  const span = ordered[originalPacketNumber - 1]
  if (!span) return null
  return { start: span.spanStart, end: span.spanEnd, dataOffset: null }
}

async function locateClassicPacketRecord(
  ctx: PacketRestoreContext,
  directory: readonly DataFrameLocation[],
  originalPacketNumber: number,
): Promise<PcapRecoveryResult<{ start: number; end: number }>> {
  const fileLen = Number(ctx.manifest.originalByteLength)
  if (!Number.isSafeInteger(fileLen) || fileLen < GLOBAL_HEADER_SIZE + 16) {
    return recoveryFail(PCAP_RECOVERY_ERROR.packetNotFound, 'original too small')
  }
  const header = await assembleSpan(ctx, directory, 0, GLOBAL_HEADER_SIZE)
  if (!header.ok) return header
  const magic = new DataView(
    header.value.buffer,
    header.value.byteOffset,
    header.value.byteLength,
  ).getUint32(0, true)
  const probe = probeClassicPcap(magic)
  wipeBytes(header.value)
  if (!probe) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'not classic PCAP')
  }
  const le = probe.endian === Endian.Little
  let offset = GLOBAL_HEADER_SIZE
  const maxPn = Math.max(ctx.index.originalPacketCount, originalPacketNumber)
  for (let n = 1; n <= maxPn; n++) {
    if (offset + 16 > fileLen) {
      return recoveryFail(PCAP_RECOVERY_ERROR.packetNotFound, 'packet past end of file')
    }
    const recHdr = await assembleSpan(ctx, directory, offset, offset + 16)
    if (!recHdr.ok) return recHdr
    const view = new DataView(recHdr.value.buffer, recHdr.value.byteOffset, recHdr.value.byteLength)
    const incl = le ? view.getUint32(8, true) : view.getUint32(8, false)
    wipeBytes(recHdr.value)
    if (incl < 0 || offset + 16 + incl > fileLen) {
      return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'invalid packet record length')
    }
    const end = offset + 16 + incl
    if (n === originalPacketNumber) {
      return recoveryOk({ start: offset, end })
    }
    offset = end
  }
  return recoveryFail(PCAP_RECOVERY_ERROR.packetNotFound, 'packet number not in capture')
}

async function locatePacketRange(
  ctx: PacketRestoreContext,
  directory: readonly DataFrameLocation[],
  originalPacketNumber: number,
): Promise<PcapRecoveryResult<{ start: number; end: number }>> {
  if (ctx.manifest.originalFormat === 'pcap') {
    return locateClassicPacketRecord(ctx, directory, originalPacketNumber)
  }
  const hinted = resolvePacketSpan(ctx.index, originalPacketNumber)
  if (hinted && hinted.end > hinted.start) {
    return recoveryOk({ start: hinted.start, end: hinted.end })
  }
  return recoveryFail(PCAP_RECOVERY_ERROR.packetNotFound, 'packet span not found')
}

function parseClassicPayload(
  record: Uint8Array,
  headerBytes: Uint8Array,
): PcapRecoveryResult<{
  linkType: number
  capturedLength: number
  originalLength: number
  payload: Uint8Array
}> {
  if (headerBytes.byteLength < GLOBAL_HEADER_SIZE) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'missing global header')
  }
  if (record.byteLength < 16) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated packet record')
  }
  const magic = new DataView(
    headerBytes.buffer,
    headerBytes.byteOffset,
    headerBytes.byteLength,
  ).getUint32(0, true)
  const probe = probeClassicPcap(magic)
  if (!probe) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'not classic PCAP header')
  }
  const le = probe.endian === Endian.Little
  const hv = new DataView(headerBytes.buffer, headerBytes.byteOffset, headerBytes.byteLength)
  const linkType = (le ? hv.getUint32(20, true) : hv.getUint32(20, false)) & 0xffff
  const rv = new DataView(record.buffer, record.byteOffset, record.byteLength)
  const capturedLength = le ? rv.getUint32(8, true) : rv.getUint32(8, false)
  const originalLength = le ? rv.getUint32(12, true) : rv.getUint32(12, false)
  if (capturedLength > record.byteLength - 16 || capturedLength < 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'invalid captured length')
  }
  return recoveryOk({
    linkType,
    capturedLength,
    originalLength,
    payload: record.subarray(16, 16 + capturedLength),
  })
}

async function sliceBytes(blob: Blob, offset: number, length: number): Promise<Uint8Array | null> {
  if (offset < 0 || length < 0 || offset + length > blob.size) return null
  const ab = await blob.slice(offset, offset + length).arrayBuffer()
  return new Uint8Array(ab)
}

async function extractAnonymizedPayload(
  anonymizedBlob: Blob | null,
  anonymizedPacketNumber: number | null,
): Promise<ArrayBuffer | undefined> {
  if (!anonymizedBlob || anonymizedPacketNumber == null || anonymizedPacketNumber < 1) {
    return undefined
  }
  if (anonymizedBlob.size > SAFE_ANON_PREVIEW_BYTES) return undefined
  try {
    const header = await sliceBytes(anonymizedBlob, 0, GLOBAL_HEADER_SIZE)
    if (!header || header.byteLength < GLOBAL_HEADER_SIZE) return undefined
    const magic = new DataView(header.buffer, header.byteOffset, header.byteLength).getUint32(0, true)
    const probe = probeClassicPcap(magic)
    if (!probe) return undefined
    const le = probe.endian === Endian.Little
    let offset = GLOBAL_HEADER_SIZE
    let n = 0
    while (offset + 16 <= anonymizedBlob.size) {
      const recHeader = await sliceBytes(anonymizedBlob, offset, 16)
      if (!recHeader || recHeader.byteLength < 16) return undefined
      const view = new DataView(recHeader.buffer, recHeader.byteOffset, recHeader.byteLength)
      const incl = le ? view.getUint32(8, true) : view.getUint32(8, false)
      if (incl < 0 || offset + 16 + incl > anonymizedBlob.size) return undefined
      n += 1
      if (n === anonymizedPacketNumber) {
        const payload = await sliceBytes(anonymizedBlob, offset + 16, incl)
        return payload ? payload.slice().buffer : undefined
      }
      offset += 16 + incl
    }
  } catch {
    return undefined
  }
  return undefined
}

async function assembleSpan(
  ctx: PacketRestoreContext,
  directory: readonly DataFrameLocation[],
  start: number,
  end: number,
): Promise<PcapRecoveryResult<Uint8Array>> {
  return assembleOriginalRange({
    recoveryBlob: ctx.recoveryBlob,
    directory,
    pieces: ctx.index.listRangePieces(),
    rangeStart: start,
    rangeEnd: end,
    cache: ctx.cache,
    restoreEncoding: ctx.manifest.restoreEncoding,
    anonymizedBlob: ctx.anonymizedBlob,
  })
}

export async function openRestoredPacket(
  ctx: PacketRestoreContext,
  hitRef: RecoveryHitRef,
): Promise<PcapRecoveryResult<RestoredPacketView>> {
  const pn = resolveOriginalPacketNumber(ctx.index, hitRef)
  if (!pn.ok) return pn

  const dir = await ensureDataFrameDirectory(ctx)
  if (!dir.ok) return dir

  const located = await locatePacketRange(ctx, dir.value, pn.value)
  if (!located.ok) return located
  const span = located.value

  const headerPart = await assembleSpan(ctx, dir.value, 0, GLOBAL_HEADER_SIZE)
  if (!headerPart.ok) return headerPart
  const recordPart = await assembleSpan(ctx, dir.value, span.start, span.end)
  if (!recordPart.ok) {
    wipeBytes(headerPart.value)
    return recordPart
  }

  try {
    const format = ctx.manifest.originalFormat
    const anonPn =
      hitRef.anonymizedPacketNumber
      ?? ctx.index.packetMap.toAnonymized(pn.value)

    if (format === 'pcap') {
      const parsed = parseClassicPayload(recordPart.value, headerPart.value)
      if (!parsed.ok) return parsed
      const payloadCopy = parsed.value.payload.slice()
      return recoveryOk({
        originalPacketNumber: pn.value,
        anonymizedPacketNumber: anonPn,
        format,
        linkType: parsed.value.linkType,
        capturedLength: parsed.value.capturedLength,
        originalLength: parsed.value.originalLength,
        originalPayload: payloadCopy.buffer,
        anonymizedPayload: await extractAnonymizedPayload(ctx.anonymizedBlob, anonPn),
        miniCaptureDerived: true,
        fileOffset: span.start,
        recordByteLength: recordPart.value.byteLength,
      })
    }

    const payloadCopy = recordPart.value.slice()
    return recoveryOk({
      originalPacketNumber: pn.value,
      anonymizedPacketNumber: anonPn,
      format,
      linkType: 1,
      capturedLength: recordPart.value.byteLength,
      originalLength: recordPart.value.byteLength,
      originalPayload: payloadCopy.buffer,
      anonymizedPayload: await extractAnonymizedPayload(ctx.anonymizedBlob, anonPn),
      miniCaptureDerived: true,
      fileOffset: span.start,
      recordByteLength: recordPart.value.byteLength,
    })
  } finally {
    wipeBytes(headerPart.value)
    wipeBytes(recordPart.value)
  }
}

/**
 * Derived mini-capture (header context + one packet). Not the full original.
 */
export async function restorePacketMiniCapture(
  ctx: PacketRestoreContext,
  hitRef: RecoveryHitRef,
): Promise<PcapRecoveryResult<{ bytes: Uint8Array; summary: RestoreSummary }>> {
  const pn = resolveOriginalPacketNumber(ctx.index, hitRef)
  if (!pn.ok) return pn

  const dir = await ensureDataFrameDirectory(ctx)
  if (!dir.ok) return dir

  const located = await locatePacketRange(ctx, dir.value, pn.value)
  if (!located.ok) return located
  const span = located.value

  const parts: Uint8Array[] = []
  try {
    const header = await assembleSpan(ctx, dir.value, 0, Math.min(GLOBAL_HEADER_SIZE, span.start))
    if (!header.ok) return header
    parts.push(header.value)
    const record = await assembleSpan(ctx, dir.value, span.start, span.end)
    if (!record.ok) {
      for (const p of parts) wipeBytes(p)
      return record
    }
    parts.push(record.value)

    const total = parts.reduce((n, p) => n + p.byteLength, 0)
    const out = new Uint8Array(total)
    let o = 0
    for (const p of parts) {
      out.set(p, o)
      o += p.byteLength
      wipeBytes(p)
    }
    parts.length = 0
    const hash = sha256(out)
    const base = ctx.manifest.originalFileName.replace(/\.(pcap|pcapng)$/i, '') || 'capture'
    const ext = ctx.manifest.originalFormat === 'pcapng' ? '.pcapng' : '.pcap'
    return recoveryOk({
      bytes: out,
      summary: {
        kind: 'mini-capture',
        fileName: `${base}.packet-${pn.value}.derived${ext}`,
        byteLength: out.byteLength,
        sha256Hex: bytesToHex(hash),
        verified: true,
        originalPacketNumber: pn.value,
      },
    })
  } catch (err) {
    for (const p of parts) wipeBytes(p)
    return recoveryFail(
      PCAP_RECOVERY_ERROR.internal,
      err instanceof Error ? err.message : 'mini-capture failed',
    )
  }
}
