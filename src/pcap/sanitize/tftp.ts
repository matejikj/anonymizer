/**
 * T20 — TFTP (RFC 1350) sanitizer: map RRQ/WRQ filename, mask DATA/ERROR text.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'

const TFTP_PORTS = new Set([69])

const OP_RRQ = 1
const OP_WRQ = 2
const OP_DATA = 3
const OP_ACK = 4
const OP_ERROR = 5
const OP_OACK = 6

export function isTftpPortHint(src: number, dst: number): boolean {
  return TFTP_PORTS.has(src) || TFTP_PORTS.has(dst)
}

export function looksLikeTftp(
  data: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
): boolean {
  if (length < 4) return false
  const op = (data[offset]! << 8) | data[offset + 1]!
  if (op < 1 || op > 6) return false
  const onWellKnown = isTftpPortHint(srcPort, dstPort)
  // DATA: opcode + block + ≤512 payload
  if (op === OP_DATA) return length >= 4 && length <= 4 + 512 && (onWellKnown || length >= 4)
  if (op === OP_ACK) return length === 4
  // ERROR: opcode + code + message + NUL — no trailing junk (avoids NetFlow v5 version=5 false positive).
  if (op === OP_ERROR) {
    if (length < 5 || length > 4 + 128) return false
    let nul = -1
    for (let i = offset + 4; i < offset + length; i++) {
      if (data[i] === 0) {
        nul = i
        break
      }
    }
    return nul === offset + length - 1
  }
  if (op === OP_OACK) {
    if (!onWellKnown && length > 512) return false
    return length >= 4
  }
  if (op === OP_RRQ || op === OP_WRQ) {
    // filename NUL mode NUL
    let nul = -1
    for (let i = offset + 2; i < offset + length; i++) {
      if (data[i] === 0) {
        nul = i
        break
      }
    }
    return nul > offset + 2
  }
  return false
}

export function sanitizeTftp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  srcPort: number,
  dstPort: number,
): AppLayerResult | null {
  if (!looksLikeTftp(buffer, offset, length, srcPort, dstPort)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const op = (buffer[offset]! << 8) | buffer[offset + 1]!

  if (op === OP_RRQ || op === OP_WRQ) {
    sanitizeRequest(buffer, offset, length, collector, mapping, intents, packetIndex, highPrivacy, issues)
    // TID ports (non-69) get a flow hint so later DATA/ACK on ephemeral ports stay TFTP-scoped.
    if (srcPort !== 69 && srcPort > 0) {
      intents?.recordPortFlowHint(`udp/${srcPort}`, 'other')
    }
    if (dstPort !== 69 && dstPort > 0) {
      intents?.recordPortFlowHint(`udp/${dstPort}`, 'other')
    }
    coverage.push({ protocol: 'tftp', offset, length, status: 'covered' })
    return { coverage, issues }
  }

  if (op === OP_DATA) {
    // opcode(2) + block(2) + data
    if (length > 4) {
      mask(collector, intents, packetIndex, offset + 4, length - 4, 'tftp-data')
    }
    coverage.push({ protocol: 'tftp', offset, length, status: 'redacted' })
    return { coverage, issues }
  }

  if (op === OP_ACK || op === OP_OACK) {
    if (op === OP_OACK && length > 2) {
      // options are non-identity; preserve structure
      coverage.push({ protocol: 'tftp', offset, length, status: 'covered' })
      return { coverage, issues }
    }
    coverage.push({ protocol: 'tftp', offset, length, status: 'covered' })
    return { coverage, issues }
  }

  if (op === OP_ERROR) {
    // opcode(2) + code(2) + message NUL
    if (length > 4) {
      const msgLen = length - 4
      // Keep trailing NUL if present
      let maskLen = msgLen
      if (buffer[offset + length - 1] === 0) maskLen = msgLen - 1
      if (maskLen > 0) {
        mask(collector, intents, packetIndex, offset + 4, maskLen, 'tftp-error-text')
      }
    }
    coverage.push({ protocol: 'tftp', offset, length, status: 'redacted' })
    return { coverage, issues }
  }

  mask(collector, intents, packetIndex, offset, length, 'tftp-unknown')
  coverage.push({ protocol: 'tftp', offset, length, status: 'unsupported' })
  return { coverage, issues }
}

function sanitizeRequest(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  issues: string[],
): void {
  const end = offset + length
  let i = offset + 2
  const nameStart = i
  while (i < end && buffer[i] !== 0) i++
  if (i >= end) {
    mask(collector, intents, packetIndex, offset + 2, length - 2, 'tftp-rrq-trunc')
    issues.push('tftp-rrq-trunc')
    return
  }
  const nameLen = i - nameStart
  if (nameLen > 0) {
    sanitizeFilename(buffer, nameStart, nameLen, collector, mapping, intents, packetIndex, highPrivacy)
  }
}

function sanitizeFilename(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
): void {
  void _mapping
  const raw = new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
  // SEP<MAC>.cnf.xml pattern — map embedded MAC if present
  const sep = /^SEP([0-9A-Fa-f]{12})\./i.exec(raw)
  if (sep) {
    const macHex = sep[1]!
    const mac = macHex.match(/.{2}/g)!.join(':').toLowerCase()
    const canon = canonicalizeIdentity('mac', mac)
    if (canon) {
      // Replace MAC hex substring length-stable via opaque path on whole filename
      const constraint = { kind: 'text-ascii' as const, byteLength: raw.length }
      const asOpaque = canonicalizeIdentity('opaque-id', raw) ?? raw
      intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', asOpaque, len, constraint, raw)
      collector.addDeferred(abs, len, ({ mapping: live }) => {
        try {
          const alias = live.aliasFor('opaque-id', asOpaque, constraint, raw)
          // Prefer remapping MAC digits inside alias shape
          const mappedMac = live.map('mac', canon).replace(/:/g, '').toUpperCase()
          const rebuilt = raw.replace(sep[1]!, mappedMac.slice(0, 12).padEnd(12, '0'))
          return computeFixedLengthAsciiBytes(abs, len, rebuilt.length === len ? rebuilt : alias)
        } catch {
          return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'tftp-name-fallback' })
        }
      }, { fallbackKind: 'text-x', protocol: 'tftp', category: 'opaque-id', packetIndex })
      return
    }
  }

  if (highPrivacy) {
    mask(collector, intents, packetIndex, abs, len, 'tftp-filename-hp')
    return
  }
  // Whole filename as one opaque token (avoids overlapping detector + opaque patches).
  const canon = canonicalizeIdentity('opaque-id', raw)
  if (!canon) {
    mask(collector, intents, packetIndex, abs, len, 'tftp-filename')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('opaque-id', canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'tftp-filename-fallback' })
    }
  }, { fallbackKind: 'text-x', protocol: 'tftp', category: 'opaque-id', packetIndex })
}

function mask(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  abs: number,
  len: number,
  domain: string,
): void {
  if (len <= 0) return
  const fill = createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain })
  collector.maskRange(abs, fill)
  intents?.recordMaskRange(packetIndex, abs, len, domain, 'tftp')
}
