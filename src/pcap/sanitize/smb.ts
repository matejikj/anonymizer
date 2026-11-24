/**
 * T27 — SMB2/3 (TCP 445 / NetBIOS 139): header opaque IDs; SESSION_SETUP → NTLMSSP/SPNEGO;
 * TREE_CONNECT UTF-16 path map; READ/WRITE/unknown → mask. SMB1 identify+mask.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import {
  looksLikeNtlmssp,
  sanitizeNtlmssp,
  looksLikeSpnego,
  sanitizeSpnego,
  decodeUtf16,
  computeFixedLengthUtf16Bytes,
} from '../protocols/application/binproto'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'

const SMB_PORTS = new Set([445, 139])
const SMB2_MAGIC = [0xfe, 0x53, 0x4d, 0x42] // \xfeSMB
const SMB1_MAGIC = [0xff, 0x53, 0x4d, 0x42] // \xffSMB

const SMB2_NEGOTIATE = 0x0000
const SMB2_SESSION_SETUP = 0x0001
const SMB2_TREE_CONNECT = 0x0003
const SMB2_CREATE = 0x0005
const SMB2_READ = 0x0008
const SMB2_WRITE = 0x0009
const SMB2_IOCTL = 0x000b
const SMB2_QUERY_DIRECTORY = 0x000e

export function isSmbPortHint(src: number, dst: number): boolean {
  return SMB_PORTS.has(src) || SMB_PORTS.has(dst)
}

export function looksLikeSmb(data: Uint8Array, offset: number, length: number): boolean {
  let o = offset
  let len = length
  // NetBIOS session message: type 0x00, length 3 bytes
  if (len >= 4 && data[o] === 0x00) {
    const nbLen = ((data[o + 1]! & 0xff) << 16) | (data[o + 2]! << 8) | data[o + 3]!
    if (nbLen + 4 <= len && nbLen >= 4) {
      o += 4
      len = nbLen
    }
  }
  if (len < 4) return false
  return (
    (data[o] === SMB2_MAGIC[0] && data[o + 1] === SMB2_MAGIC[1]
      && data[o + 2] === SMB2_MAGIC[2] && data[o + 3] === SMB2_MAGIC[3])
    || (data[o] === SMB1_MAGIC[0] && data[o + 1] === SMB1_MAGIC[1]
      && data[o + 2] === SMB1_MAGIC[2] && data[o + 3] === SMB1_MAGIC[3])
  )
}

export function sanitizeSmb(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeSmb(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  let cursor = offset
  let end = offset + length
  if (length >= 4 && buffer[offset] === 0x00) {
    const nbLen = ((buffer[offset + 1]! & 0xff) << 16) | (buffer[offset + 2]! << 8) | buffer[offset + 3]!
    coverage.push({ protocol: 'netbios-ssn', offset, length: 4, status: 'covered' })
    cursor = offset + 4
    end = Math.min(offset + 4 + nbLen, offset + length)
  }

  while (cursor + 4 <= end) {
    if (
      buffer[cursor] === SMB1_MAGIC[0]
      && buffer[cursor + 1] === SMB1_MAGIC[1]
      && buffer[cursor + 2] === SMB1_MAGIC[2]
      && buffer[cursor + 3] === SMB1_MAGIC[3]
    ) {
      mask(collector, intents, packetIndex, cursor, end - cursor, 'smb1')
      coverage.push({ protocol: 'smb1', offset: cursor, length: end - cursor, status: 'redacted' })
      issues.push('smb1-identify-mask')
      break
    }
    if (!(
      buffer[cursor] === SMB2_MAGIC[0]
      && buffer[cursor + 1] === SMB2_MAGIC[1]
      && buffer[cursor + 2] === SMB2_MAGIC[2]
      && buffer[cursor + 3] === SMB2_MAGIC[3]
    )) {
      mask(collector, intents, packetIndex, cursor, end - cursor, 'smb-unknown')
      coverage.push({ protocol: 'smb', offset: cursor, length: end - cursor, status: 'unsupported' })
      break
    }

    if (cursor + 64 > end) {
      mask(collector, intents, packetIndex, cursor, end - cursor, 'smb2-trunc')
      coverage.push({ protocol: 'smb2', offset: cursor, length: end - cursor, status: 'malformed' })
      issues.push('smb2-header-trunc')
      break
    }

    const headerLen = readU16LE(buffer, cursor + 4)
    const cmd = readU16LE(buffer, cursor + 12)
    const nextCommand = readU32LE(buffer, cursor + 20)
    // MessageId at 24 (8), SessionId at 40 (8), TreeId at 36 (4) — SMB2 header layout:
    // 0 magic(4) 4 StructureSize(2) 6 CreditCharge(2) 8 Status(4) 12 Command(2)
    // 14 Credit(2) 16 Flags(4) 20 NextCommand(4) 24 MessageId(8) 32 ProcessId?/Reserved
    // Standard SMB2 header 64 bytes: TreeId @ 36, SessionId @ 40
    coverage.push({ protocol: 'smb2', offset: cursor, length: 64, status: 'covered' })
    mapOpaqueU64(buffer, cursor + 24, collector, mapping, intents, packetIndex, 'smb-msgid')
    mapOpaqueU32(buffer, cursor + 36, collector, mapping, intents, packetIndex, 'smb-tree')
    mapOpaqueU64(buffer, cursor + 40, collector, mapping, intents, packetIndex, 'smb-session')

    const bodyOff = cursor + 64
    let bodyEnd = end
    if (nextCommand !== 0 && cursor + nextCommand <= end) {
      bodyEnd = cursor + nextCommand
    }
    const bodyLen = bodyEnd - bodyOff
    if (bodyLen > 0) {
      sanitizeSmb2Body(
        buffer, bodyOff, bodyLen, cmd, collector, mapping, intents, packetIndex, coverage, issues,
      )
    }

    if (nextCommand === 0) break
    if (nextCommand < 64 || cursor + nextCommand > end) {
      issues.push('smb2-compound-bad')
      break
    }
    cursor += nextCommand
    void headerLen
  }

  return { coverage, issues }
}

function sanitizeSmb2Body(
  buffer: Uint8Array,
  offset: number,
  length: number,
  cmd: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  switch (cmd) {
    case SMB2_NEGOTIATE:
      // Dialects/capabilities preserve; ClientGuid at fixed offset in request (StructureSize 36)
      if (length >= 36) {
        // ClientGuid 16 bytes at +16 from body start (after StructureSize/DialectCount/SecurityMode/…)
        // Request: StructureSize(2) DialectCount(2) SecurityMode(2) Reserved(2) Capabilities(4) ClientGuid(16)
        mapOpaqueGuid(buffer, offset + 8, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'smb2-negotiate', offset, length, status: 'covered' })
      } else {
        coverage.push({ protocol: 'smb2-negotiate', offset, length, status: 'covered' })
      }
      return
    case SMB2_SESSION_SETUP:
      sanitizeSessionSetup(buffer, offset, length, collector, mapping, intents, packetIndex, coverage, issues)
      return
    case SMB2_TREE_CONNECT:
      sanitizeTreeConnect(buffer, offset, length, collector, mapping, intents, packetIndex, coverage)
      return
    case SMB2_CREATE:
    case SMB2_QUERY_DIRECTORY:
      // File names UTF-16 — mask fail-closed (path detectors later via T42)
      mask(collector, intents, packetIndex, offset, length, 'smb2-path-body')
      coverage.push({ protocol: 'smb2-path', offset, length, status: 'redacted' })
      return
    case SMB2_READ:
    case SMB2_WRITE:
    case SMB2_IOCTL:
      mask(collector, intents, packetIndex, offset, length, 'smb2-data')
      coverage.push({ protocol: 'smb2-data', offset, length, status: 'redacted' })
      return
    default:
      mask(collector, intents, packetIndex, offset, length, `smb2-cmd-${cmd}`)
      coverage.push({ protocol: 'smb2-cmd', offset, length, status: 'redacted' })
  }
}

function sanitizeSessionSetup(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  // SESSION_SETUP request: StructureSize(2) Flags(1) SecurityMode(1) Capabilities(4)
  // Channel(4) SecurityBufferOffset(2) SecurityBufferLength(2) PreviousSessionId(8) + buffer
  if (length < 24) {
    mask(collector, intents, packetIndex, offset, length, 'smb2-session-trunc')
    coverage.push({ protocol: 'smb2-session', offset, length, status: 'malformed' })
    return
  }
  const secOff = readU16LE(buffer, offset + 12)
  const secLen = readU16LE(buffer, offset + 14)
  // SecurityBufferOffset is from start of SMB2 header (= body-64). Absolute = body + (secOff - 64)
  const secAbs = offset - 64 + secOff
  coverage.push({ protocol: 'smb2-session', offset, length: Math.min(24, length), status: 'covered' })
  if (secLen === 0) return
  if (secAbs < offset || secAbs + secLen > offset + length) {
    // Response layout differs (StructureSize 9): SecurityBufferOffset(2) Length(2) at +4
    const altOff = readU16LE(buffer, offset + 4)
    const altLen = readU16LE(buffer, offset + 6)
    const altAbs = offset - 64 + altOff
    if (altLen > 0 && altAbs >= offset && altAbs + altLen <= offset + length) {
      sanitizeSecurityBuffer(buffer, altAbs, altLen, collector, mapping, intents, packetIndex, coverage, issues)
      return
    }
    mask(collector, intents, packetIndex, offset + 24, length - 24, 'smb2-secbuf')
    coverage.push({ protocol: 'smb2-secbuf', offset: offset + 24, length: length - 24, status: 'redacted' })
    issues.push('smb2-secbuf-bounds')
    return
  }
  sanitizeSecurityBuffer(buffer, secAbs, secLen, collector, mapping, intents, packetIndex, coverage, issues)
}

function sanitizeSecurityBuffer(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (looksLikeNtlmssp(buffer, abs, len)) {
    sanitizeNtlmssp(buffer, abs, len, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'smb2-ntlm', offset: abs, length: len, status: 'covered' })
    return
  }
  if (looksLikeSpnego(buffer, abs, len)) {
    sanitizeSpnego(buffer, abs, len, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'smb2-spnego', offset: abs, length: len, status: 'covered' })
    return
  }
  mask(collector, intents, packetIndex, abs, len, 'smb2-secbuf-unknown')
  coverage.push({ protocol: 'smb2-secbuf', offset: abs, length: len, status: 'redacted' })
  issues.push('smb2-secbuf-unknown')
}

function sanitizeTreeConnect(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  // TREE_CONNECT request: StructureSize(2) Flags/Reserved(2) PathOffset(2) PathLength(2) + Path
  if (length < 8) {
    mask(collector, intents, packetIndex, offset, length, 'smb2-tree-trunc')
    coverage.push({ protocol: 'smb2-tree', offset, length, status: 'malformed' })
    return
  }
  const pathOff = readU16LE(buffer, offset + 4)
  const pathLen = readU16LE(buffer, offset + 6)
  const pathAbs = offset - 64 + pathOff
  coverage.push({ protocol: 'smb2-tree', offset, length: 8, status: 'covered' })
  if (pathLen === 0 || pathAbs < offset || pathAbs + pathLen > offset + length) {
    if (length > 8) {
      mask(collector, intents, packetIndex, offset + 8, length - 8, 'smb2-tree-path')
      coverage.push({ protocol: 'smb2-tree-path', offset: offset + 8, length: length - 8, status: 'redacted' })
    }
    return
  }
  mapUncPath(buffer, pathAbs, pathLen, collector, mapping, intents, packetIndex)
  coverage.push({ protocol: 'smb2-tree-path', offset: pathAbs, length: pathLen, status: 'covered' })
}

/** \\server\share — map server as hostname; mask share name (may be sensitive). */
function mapUncPath(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const slice = buffer.subarray(abs, abs + len)
  const text = decodeUtf16(slice, 'le')
  if (!text) {
    mask(collector, intents, packetIndex, abs, len, 'smb2-path-utf16')
    return
  }
  // \\server\share
  const m = /^\\\\([^\\]+)(\\.*)?$/.exec(text)
  if (!m) {
    mask(collector, intents, packetIndex, abs, len, 'smb2-path-shape')
    return
  }
  const server = m[1]!
  const rest = m[2] ?? ''
  const serverCanon = canonicalizeIdentity('hostname', server.toLowerCase())
  if (!serverCanon) {
    mask(collector, intents, packetIndex, abs, len, 'smb2-path-host')
    return
  }
  // Build length-stable UTF-16 replacement: \\ + aliasServer + rest (rest masked to x)
  const constraint = { kind: 'text-ascii' as const, byteLength: server.length }
  intents?.recordEntityReplacement(
    packetIndex, abs + 4, 'hostname', serverCanon, server.length * 2, constraint, server,
  )
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const aliasHost = live.aliasFor('hostname', serverCanon, constraint, server)
      const hostWire = aliasHost.length === server.length
        ? aliasHost
        : aliasHost.slice(0, server.length).padEnd(server.length, 'x')
      const restMasked = rest.replace(/[^\u0000]/g, 'x')
      const outText = `\\\\${hostWire}${restMasked}`
      return computeFixedLengthUtf16Bytes(len, outText, 'le')
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'smb2-unc' })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'smb', category: 'hostname', packetIndex })
  void mapping
}

function mapOpaqueU64(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  const lo = readU32LE(buffer, offset)
  const hi = readU32LE(buffer, offset + 4)
  if (lo === 0 && hi === 0) return
  const canon = `${domain}/${hi.toString(16)}-${lo.toString(16)}`
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, 8)
  collector.addDeferred(offset, 8, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: 8, packetIndex, offset, domain: `${domain}:${alias}`,
    })
  })
  void mapping
}

function mapOpaqueU32(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  const v = readU32LE(buffer, offset)
  if (v === 0) return
  const canon = `${domain}/${v.toString(16)}`
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, 4)
  collector.addDeferred(offset, 4, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: 4, packetIndex, offset, domain: `${domain}:${alias}`,
    })
  })
  void mapping
}

function mapOpaqueGuid(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  let hex = ''
  for (let i = 0; i < 16; i++) hex += buffer[offset + i]!.toString(16).padStart(2, '0')
  if (/^0+$/.test(hex)) return
  const canon = `smb-guid/${hex}`
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, 16)
  collector.addDeferred(offset, 16, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: 16, packetIndex, offset, domain: `smb-guid:${alias}`,
    })
  })
  void mapping
}

function mask(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'smb')
  collector.addDeferred(offset, length, () => createProtocolNeutralMaskFill({
    length, packetIndex, offset, domain,
  }))
}

function readU16LE(b: Uint8Array, o: number): number {
  return b[o]! | (b[o + 1]! << 8)
}

function readU32LE(b: Uint8Array, o: number): number {
  return (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0
}
