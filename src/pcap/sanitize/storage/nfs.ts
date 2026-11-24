/**
 * T42 — NFS v3/v4 over ONC RPC (TCP/UDP 2049): AUTH_SYS; file content mask; handles opaque.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { mapAsciiIdentity, maskBytes, readU32be } from './common.ts'
import { looksLikeOncRpcCall, sanitizeOncRpcMessage } from './oncRpc.ts'

export const NFS_PORT = 2049
export const NFS_PROG = 100_003

/** NFSv3 procedures with file data in args/results. */
const NFS3_READ = 6
const NFS3_WRITE = 7
const NFS3_READDIR = 16
const NFS3_READDIRPLUS = 17
const NFS3_LOOKUP = 3
const NFS3_CREATE = 8
const NFS3_MKDIR = 9
const NFS3_SYMLINK = 10
const NFS3_RENAME = 11

export function isNfsPortHint(src: number, dst: number): boolean {
  return src === NFS_PORT || dst === NFS_PORT
}

export function looksLikeNfs(buffer: Uint8Array, offset: number, length: number): boolean {
  return looksLikeOncRpcCall(buffer, offset, length, NFS_PROG)
}

export function sanitizeNfs(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  highPrivacy: boolean,
  intents?: IntentCollector,
  transport: 'tcp' | 'udp' = 'tcp',
): AppLayerResult | null {
  if (!isNfsPortHint(srcPort, dstPort) && !looksLikeNfs(buffer, offset, length)) {
    return null
  }

  // Track last CALL proc for matching REPLY on same datagram (UDP) — single message baseline.
  let lastProc = -1
  let lastVers = 0

  const result = sanitizeOncRpcMessage({
    buffer,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
    highPrivacy,
    transport,
    protocol: 'nfs',
    onCallBody: (bodyOff, bodyLen, prog, vers, proc) => {
      if (prog !== NFS_PROG) {
        maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'nfs-prog', 'nfs')
        return
      }
      lastProc = proc
      lastVers = vers
      sanitizeNfsCallBody(
        buffer,
        bodyOff,
        bodyLen,
        vers,
        proc,
        collector,
        mapping,
        intents,
        packetIndex,
      )
    },
    onReplyBody: (bodyOff, bodyLen, _prog, _vers, _proc) => {
      sanitizeNfsReplyBody(
        buffer,
        bodyOff,
        bodyLen,
        lastVers,
        lastProc,
        collector,
        mapping,
        intents,
        packetIndex,
      )
    },
  })

  if (result) {
    // Ensure parent coverage id nfs for family prefix rules
    return {
      coverage: [
        ...result.coverage,
        { protocol: 'nfs', offset, length, status: 'covered' as const },
      ],
      issues: result.issues,
    }
  }
  return null
}

function sanitizeNfsCallBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
  vers: number,
  proc: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (length <= 0) return
  // File handle at start of many v3 ops: len(4) + bytes + pad
  let p = offset
  const end = offset + length
  p = mapFileHandle(buffer, p, end, collector, mapping, intents, packetIndex)

  if (vers === 3 && (proc === NFS3_WRITE || proc === NFS3_READ)) {
    // After handle: offset/count … then data for WRITE
    if (proc === NFS3_WRITE) {
      // Skip offset(8)+count(4)+stable(4) roughly — mask remaining as file data
      const hdr = Math.min(16, end - p)
      p += hdr
      if (p < end) {
        maskBytes(collector, intents, packetIndex, p, end - p, 'nfs-data', 'nfs')
      }
      return
    }
  }

  if (
    vers === 3
    && (proc === NFS3_LOOKUP
      || proc === NFS3_CREATE
      || proc === NFS3_MKDIR
      || proc === NFS3_SYMLINK
      || proc === NFS3_RENAME)
  ) {
    mapXdrString(buffer, p, end, collector, mapping, intents, packetIndex, 'opaque-id')
    // Remainder (attrs / symlink target) mask
    // Remap cursor loosely — mask leftover
    const rem = scanPastXdrString(buffer, p, end)
    if (rem < end) {
      if (proc === NFS3_SYMLINK) {
        mapXdrString(buffer, rem, end, collector, mapping, intents, packetIndex, 'opaque-id')
      } else {
        maskBytes(collector, intents, packetIndex, rem, end - rem, 'nfs-body', 'nfs')
      }
    }
    return
  }

  if (vers >= 4) {
    // NFSv4 compound — mask opaque body (ops dictionary baseline)
    maskBytes(collector, intents, packetIndex, offset, length, 'nfs-v4', 'nfs')
    return
  }

  if (p < end) {
    maskBytes(collector, intents, packetIndex, p, end - p, 'nfs-body', 'nfs')
  }
}

function sanitizeNfsReplyBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
  vers: number,
  proc: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (length <= 0) return
  const end = offset + length
  // status
  if (length < 4) {
    maskBytes(collector, intents, packetIndex, offset, length, 'nfs-reply', 'nfs')
    return
  }
  // Preserve status word
  let p = offset + 4
  if (vers === 3 && (proc === NFS3_READ || proc === NFS3_READDIR || proc === NFS3_READDIRPLUS)) {
    // Mask data payload after status/attrs header — conservative: mask from first large opaque
    maskBytes(collector, intents, packetIndex, p, end - p, 'nfs-data', 'nfs')
    return
  }
  if (vers === 3 && proc === NFS3_LOOKUP) {
    p = mapFileHandle(buffer, p, end, collector, mapping, intents, packetIndex)
    if (p < end) {
      maskBytes(collector, intents, packetIndex, p, end - p, 'nfs-body', 'nfs')
    }
    return
  }
  if (vers >= 4) {
    maskBytes(collector, intents, packetIndex, offset, length, 'nfs-v4', 'nfs')
    return
  }
  // Default: map leading file handle if present, mask rest
  p = mapFileHandle(buffer, p, end, collector, mapping, intents, packetIndex)
  if (p < end) {
    maskBytes(collector, intents, packetIndex, p, end - p, 'nfs-body', 'nfs')
  }
}

function mapFileHandle(
  buffer: Uint8Array,
  offset: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): number {
  if (offset + 4 > end) return offset
  const len = readU32be(buffer, offset)
  if (len === 0 || len > 128 || offset + 4 + len > end) return offset
  const pad = (len + 3) & ~3
  // Opaque handle → mask (consistent fill; not text identity)
  maskBytes(collector, intents, packetIndex, offset + 4, len, 'nfs-fh', 'nfs')
  void mapping
  return offset + 4 + pad
}

function mapXdrString(
  buffer: Uint8Array,
  offset: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  category: 'opaque-id' | 'hostname' | 'user-id',
): void {
  if (offset + 4 > end) return
  const len = readU32be(buffer, offset)
  if (len === 0 || offset + 4 + len > end) return
  mapAsciiIdentity(
    buffer,
    offset + 4,
    len,
    category,
    collector,
    mapping,
    intents,
    packetIndex,
    'nfs',
  )
}

function scanPastXdrString(buffer: Uint8Array, offset: number, end: number): number {
  if (offset + 4 > end) return offset
  const len = readU32be(buffer, offset)
  if (offset + 4 + len > end) return end
  const pad = (len + 3) & ~3
  return offset + 4 + pad
}
