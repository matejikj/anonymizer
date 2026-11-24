/**
 * T52 — SMPP 3.4/5.0 baseline: TCP 2775; bind secrets; addresses map; SMS body always mask.
 */

import type { PatchCollector } from './PatchCollector.ts'
import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import type { IdentityCategory } from '../../mapping/identityCategories.ts'
import { createProtocolNeutralMaskFill } from './maskFill.ts'
import { computeFixedLengthAsciiBytes } from './textPatch.ts'
import { smppTransportSessionForMapping, type SmppTransportSession } from './smpp/smppSessionGraph.ts'

export const SMPP_TCP_PORT = 2775

const MAX_PDU = 65_536
const MAX_PDUS = 32

/** Request command_ids (response = id | 0x80000000). */
const CMD = {
  BIND_RECEIVER: 0x0000_0001,
  BIND_TRANSMITTER: 0x0000_0002,
  QUERY_SM: 0x0000_0003,
  SUBMIT_SM: 0x0000_0004,
  DELIVER_SM: 0x0000_0005,
  UNBIND: 0x0000_0006,
  REPLACE_SM: 0x0000_0007,
  CANCEL_SM: 0x0000_0008,
  BIND_TRANSCEIVER: 0x0000_0009,
  OUTBIND: 0x0000_000b,
  ENQUIRE_LINK: 0x0000_0015,
  SUBMIT_MULTI: 0x0000_0021,
  ALERT_NOTIFICATION: 0x0000_0102,
  DATA_SM: 0x0000_0103,
} as const

const KNOWN_CMD = new Set<number>([
  ...Object.values(CMD),
  ...Object.values(CMD).map((id) => id | 0x8000_0000),
])

/** Optional TLV tags (SMPP 3.4 / 5.0). */
const TLV_MESSAGE_PAYLOAD = 0x0424
const TLV_RECEIPTED_MESSAGE_ID = 0x001e
const TLV_CALLBACK_NUM = 0x0381
const TLV_SAR_MSG_REF = 0x020c
const TLV_SAR_TOTAL = 0x020e
const TLV_SAR_SEQ = 0x020f
const TLV_MESSAGE_STATE = 0x0427
const TLV_NETWORK_ERROR = 0x0423
const TLV_DEST_ADDR_SUBUNIT = 0x0005
const TLV_SOURCE_ADDR_SUBUNIT = 0x000d

export function isSmppPortHint(src: number, dst: number): boolean {
  return src === SMPP_TCP_PORT || dst === SMPP_TCP_PORT
}

export function looksLikeSmpp(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 16) return false
  const cmdLen = readU32(buffer, offset)
  if (cmdLen < 16 || cmdLen > MAX_PDU) return false
  if (cmdLen > length && length < 16) return false
  const cmdId = readU32(buffer, offset + 4)
  if (!KNOWN_CMD.has(cmdId) && (cmdId & 0x7fff_ffff) > 0x0000_0200) return false
  // First PDU length may exceed segment (reassembly) — still a hint if header looks valid
  if (cmdLen <= length) return true
  // Partial first PDU: accept when port-hinted callers already filtered
  return KNOWN_CMD.has(cmdId) || (cmdId & 0x7fff_ffff) <= 0x0000_0200
}

export interface SmppSanitizeContext {
  readonly transportSessionKey: string
}

export function sanitizeSmpp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  context?: SmppSanitizeContext,
): AppLayerResult | null {
  if (!looksLikeSmpp(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const transportKey = context?.transportSessionKey ?? 'smpp:unknown-transport'
  const transportSession = smppTransportSessionForMapping(mapping, transportKey)
  let pos = offset
  const end = offset + length
  let n = 0

  while (pos + 16 <= end && n < MAX_PDUS) {
    n++
    const cmdLen = readU32(buffer, pos)
    if (cmdLen < 16 || cmdLen > MAX_PDU) {
      maskRange(collector, intents, packetIndex, pos, end - pos, 'smpp-bad-len')
      coverage.push({ protocol: 'smpp', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('smpp-bad-command-length')
      break
    }
    if (pos + cmdLen > end) {
      // Incomplete PDU
      maskRange(collector, intents, packetIndex, pos, end - pos, 'smpp-partial')
      coverage.push({
        protocol: 'smpp',
        offset: pos,
        length: end - pos,
        status: 'requires-reassembly',
      })
      issues.push('smpp-requires-reassembly')
      break
    }
    sanitizePdu(
      buffer,
      pos,
      cmdLen,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
      transportSession,
      transportKey,
    )
    pos += cmdLen
  }

  if (pos < end && n > 0) {
    // Trailing bytes after complete PDUs
    maskRange(collector, intents, packetIndex, pos, end - pos, 'smpp-trailer')
    coverage.push({
      protocol: 'smpp-body',
      offset: pos,
      length: end - pos,
      status: 'redacted',
    })
  }

  if (coverage.length === 0) return null
  coverage.unshift({ protocol: 'smpp', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizePdu(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  transportSession: SmppTransportSession,
  transportSessionKey: string,
): void {
  const resolveAccountScope = (): string =>
    transportSession.accountScope || `unbound:${transportSessionKey}`
  const resolveMidPrefix = (): string => `smpp-mid:${resolveAccountScope()}:`
  const cmdId = readU32(buffer, offset + 4)
  const status = readU32(buffer, offset + 8)
  coverage.push({ protocol: 'smpp-hdr', offset, length: 16, status: 'covered' })

  const bodyOff = offset + 16
  const bodyLen = length - 16
  if (bodyLen <= 0) {
    coverage.push({ protocol: 'smpp', offset, length, status: 'covered' })
    return
  }

  const req = cmdId & 0x7fff_ffff
  const isResp = (cmdId & 0x8000_0000) !== 0

  // Failed response may omit body — still walk if present
  if (isResp && status !== 0 && bodyLen < 2) {
    coverage.push({ protocol: 'smpp', offset, length, status: 'covered' })
    return
  }

  let cursor = bodyOff
  const bodyEnd = bodyOff + bodyLen

  try {
    if (!isResp && isBind(req)) {
      cursor = sanitizeBindBody(
        buffer,
        cursor,
        bodyEnd,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
        transportSession,
      )
    } else if (isResp && isBind(req)) {
      // bind_*_resp: system_id C-Octet
      const systemIdStart = cursor
      cursor = readMapCOctet(
        buffer,
        cursor,
        bodyEnd,
        16,
        'user-id',
        'smpp-system',
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
      )
      const systemId = readCOctet(buffer, systemIdStart, bodyEnd, 16).text
      if (systemId) {
        transportSession.accountScope = systemId
      }
    } else if (
      (!isResp && (req === CMD.SUBMIT_SM || req === CMD.DELIVER_SM || req === CMD.DATA_SM || req === CMD.REPLACE_SM))
      || (!isResp && req === CMD.SUBMIT_MULTI)
    ) {
      cursor = sanitizeSubmitLike(
        buffer,
        cursor,
        bodyEnd,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
        req === CMD.DATA_SM,
        req === CMD.SUBMIT_MULTI,
      )
    } else if (isResp && (req === CMD.SUBMIT_SM || req === CMD.DATA_SM || req === CMD.SUBMIT_MULTI)) {
      const midStart = cursor
      cursor = readMapCOctet(
        buffer,
        cursor,
        bodyEnd,
        65,
        'opaque-id',
        'smpp-msgid',
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        resolveMidPrefix(),
      )
      const midRaw = readCOctet(buffer, midStart, bodyEnd, 65).text
      if (midRaw) {
        transportSession.graph.noteSubmit(resolveAccountScope(), midRaw, packetIndex)
        issues.push('smpp-session-submit')
      }
    } else if (!isResp && (req === CMD.QUERY_SM || req === CMD.CANCEL_SM)) {
      cursor = readMapCOctet(
        buffer,
        cursor,
        bodyEnd,
        65,
        'opaque-id',
        'smpp-msgid',
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        resolveMidPrefix(),
      )
      // source_addr_ton/npi + source_addr
      if (cursor + 2 <= bodyEnd) {
        coverage.push({ protocol: 'smpp', offset: cursor, length: 2, status: 'covered' })
        cursor += 2
        cursor = readMapAddr(
          buffer,
          cursor,
          bodyEnd,
          21,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
        )
      }
    } else if (!isResp && req === CMD.ENQUIRE_LINK) {
      // no body
    } else if (!isResp && req === CMD.UNBIND) {
      // no body
    } else if (bodyLen > 0 && !KNOWN_CMD.has(cmdId)) {
      maskRange(collector, intents, packetIndex, bodyOff, bodyLen, 'smpp-unknown-cmd')
      coverage.push({
        protocol: 'smpp-body',
        offset: bodyOff,
        length: bodyLen,
        status: 'redacted',
      })
      issues.push('smpp-unknown-command')
      return
    }

    // Optional TLVs after mandatory
    if (cursor < bodyEnd) {
      sanitizeTlvs(
        buffer,
        cursor,
        bodyEnd,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
        transportSession,
        resolveAccountScope,
        resolveMidPrefix,
      )
    }
  } catch {
    maskRange(collector, intents, packetIndex, cursor, Math.max(0, bodyEnd - cursor), 'smpp-parse')
    coverage.push({
      protocol: 'smpp-body',
      offset: cursor,
      length: Math.max(0, bodyEnd - cursor),
      status: 'malformed',
    })
    issues.push('smpp-parse-error')
  }
}

function isBind(req: number): boolean {
  return (
    req === CMD.BIND_RECEIVER
    || req === CMD.BIND_TRANSMITTER
    || req === CMD.BIND_TRANSCEIVER
  )
}

function sanitizeBindBody(
  buffer: Uint8Array,
  cursor: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  transportSession: SmppTransportSession,
): number {
  const systemIdStart = cursor
  cursor = readMapCOctet(
    buffer,
    cursor,
    end,
    16,
    'user-id',
    'smpp-system',
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
  )
  const systemId = readCOctet(buffer, systemIdStart, end, 16).text
  if (systemId) {
    transportSession.accountScope = systemId
  }
  // password — always mask
  cursor = readMaskCOctet(buffer, cursor, end, 9, collector, intents, packetIndex, coverage, issues)
  cursor = readMapCOctet(
    buffer,
    cursor,
    end,
    13,
    'opaque-id',
    'smpp-systype',
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    'smpp-st:',
  )
  if (cursor + 3 > end) return cursor
  // interface_version, addr_ton, addr_npi
  coverage.push({ protocol: 'smpp', offset: cursor, length: 3, status: 'covered' })
  cursor += 3
  cursor = readMapCOctet(
    buffer,
    cursor,
    end,
    41,
    'opaque-id',
    'smpp-range',
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    'smpp-ar:',
  )
  return cursor
}

function sanitizeSubmitLike(
  buffer: Uint8Array,
  cursor: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  isDataSm: boolean,
  isMulti: boolean,
): number {
  // service_type
  cursor = readMapCOctet(
    buffer,
    cursor,
    end,
    6,
    'opaque-id',
    'smpp-svc',
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    'smpp-svc:',
  )
  if (cursor + 2 > end) return cursor
  coverage.push({ protocol: 'smpp', offset: cursor, length: 2, status: 'covered' }) // ton/npi
  cursor += 2
  cursor = readMapAddr(buffer, cursor, end, 21, collector, mapping, intents, packetIndex, coverage)
  if (cursor + 2 > end) return cursor
  coverage.push({ protocol: 'smpp', offset: cursor, length: 2, status: 'covered' })
  cursor += 2
  cursor = readMapAddr(buffer, cursor, end, 21, collector, mapping, intents, packetIndex, coverage)

  if (isMulti) {
    // number_of_dests (1) + dest_address(es) — mask remainder of mandatory as fail-closed
    if (cursor < end) {
      // Keep counts readable: first byte = number_of_dests
      if (cursor < end) {
        coverage.push({ protocol: 'smpp', offset: cursor, length: 1, status: 'covered' })
        const nDest = buffer[cursor]!
        cursor += 1
        // Each dest: flag(1)+ton+npi+addr — mask block for baseline
        const rem = Math.min(end - cursor, nDest * 24)
        if (rem > 0) {
          maskRange(collector, intents, packetIndex, cursor, rem, 'smpp-multi-dest')
          coverage.push({
            protocol: 'smpp-body',
            offset: cursor,
            length: rem,
            status: 'redacted',
          })
          cursor += rem
        }
      }
    }
  }

  if (isDataSm) {
    // esm_class, registered_delivery, data_coding — then TLVs only (no short_message)
    if (cursor + 3 <= end) {
      coverage.push({ protocol: 'smpp', offset: cursor, length: 3, status: 'covered' })
      cursor += 3
    }
    return cursor
  }

  // esm_class, protocol_id, priority_flag
  if (cursor + 3 > end) return cursor
  coverage.push({ protocol: 'smpp', offset: cursor, length: 3, status: 'covered' })
  cursor += 3
  // schedule_delivery_time, validity_period — C-Octet times (map opaque / mask free text)
  cursor = readMapCOctet(
    buffer,
    cursor,
    end,
    17,
    'opaque-id',
    'smpp-time',
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    'smpp-t:',
  )
  cursor = readMapCOctet(
    buffer,
    cursor,
    end,
    17,
    'opaque-id',
    'smpp-time',
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    'smpp-t:',
  )
  // registered_delivery, replace_if_present, data_coding, sm_default_msg_id
  if (cursor + 4 > end) return cursor
  coverage.push({ protocol: 'smpp', offset: cursor, length: 4, status: 'covered' })
  cursor += 4
  if (cursor >= end) return cursor
  const smLen = buffer[cursor]!
  coverage.push({ protocol: 'smpp', offset: cursor, length: 1, status: 'covered' })
  cursor += 1
  if (smLen > 0) {
    if (cursor + smLen > end) {
      maskRange(collector, intents, packetIndex, cursor, end - cursor, 'smpp-sm-trunc')
      coverage.push({
        protocol: 'smpp-sm',
        offset: cursor,
        length: end - cursor,
        status: 'malformed',
      })
      issues.push('smpp-short-message-trunc')
      return end
    }
    // Always mask SMS / DLR body (both levels)
    maskRange(collector, intents, packetIndex, cursor, smLen, 'smpp-sm')
    coverage.push({
      protocol: 'smpp-sm',
      offset: cursor,
      length: smLen,
      status: 'redacted',
    })
    issues.push('smpp-short-message-masked')
    cursor += smLen
  }
  return cursor
}

function sanitizeTlvs(
  buffer: Uint8Array,
  offset: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  transportSession: SmppTransportSession,
  resolveAccountScope: () => string,
  resolveMidPrefix: () => string,
): void {
  let pos = offset
  let n = 0
  while (pos + 4 <= end && n < 64) {
    n++
    const tag = (buffer[pos]! << 8) | buffer[pos + 1]!
    const len = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    if (pos + 4 + len > end) {
      maskRange(collector, intents, packetIndex, pos, end - pos, 'smpp-tlv-trunc')
      coverage.push({
        protocol: 'smpp-tlv',
        offset: pos,
        length: end - pos,
        status: 'malformed',
      })
      issues.push('smpp-tlv-trunc')
      return
    }
    coverage.push({ protocol: 'smpp-tlv-hdr', offset: pos, length: 4, status: 'covered' })
    const valOff = pos + 4
    if (len > 0) {
      if (tag === TLV_MESSAGE_PAYLOAD || tag === TLV_CALLBACK_NUM) {
        maskRange(collector, intents, packetIndex, valOff, len, 'smpp-tlv-content')
        coverage.push({
          protocol: 'smpp-sm',
          offset: valOff,
          length: len,
          status: 'redacted',
        })
        issues.push('smpp-tlv-content-masked')
      } else if (tag === TLV_RECEIPTED_MESSAGE_ID) {
        const midText = new TextDecoder('latin1').decode(buffer.subarray(valOff, valOff + len))
        const fact = transportSession.graph.noteDeliver(
          resolveAccountScope(),
          midText.replace(/\0.*$/, ''),
          packetIndex,
        )
        if (fact) issues.push('smpp-session-dlr')
        mapBytesAsOpaque(
          buffer,
          valOff,
          len,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
          resolveMidPrefix(),
        )
      } else if (tag === TLV_SAR_MSG_REF) {
        mapBytesAsOpaque(
          buffer,
          valOff,
          len,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
          'smpp-sar:',
        )
      } else if (
        tag === TLV_SAR_TOTAL
        || tag === TLV_SAR_SEQ
        || tag === TLV_MESSAGE_STATE
        || tag === TLV_NETWORK_ERROR
        || tag === TLV_DEST_ADDR_SUBUNIT
        || tag === TLV_SOURCE_ADDR_SUBUNIT
      ) {
        coverage.push({ protocol: 'smpp-tlv', offset: valOff, length: len, status: 'covered' })
      } else {
        maskRange(collector, intents, packetIndex, valOff, len, `smpp-tlv-${tag}`)
        coverage.push({
          protocol: 'smpp-tlv',
          offset: valOff,
          length: len,
          status: 'redacted',
        })
      }
    }
    pos += 4 + len
  }
}

function readMapAddr(
  buffer: Uint8Array,
  cursor: number,
  end: number,
  maxLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): number {
  const parsed = readCOctet(buffer, cursor, end, maxLen)
  if (parsed.bytes === 0) return cursor
  if (parsed.text.length === 0) {
    coverage.push({ protocol: 'smpp-addr', offset: cursor, length: parsed.bytes, status: 'covered' })
    return cursor + parsed.bytes
  }
  const phone = isPhoneLike(parsed.text)
  mapAscii(
    buffer,
    cursor,
    parsed.text.length,
    phone ? 'sip-phone' : 'opaque-id',
    collector,
    mapping,
    intents,
    packetIndex,
    phone ? undefined : 'smpp-alpha:',
  )
  // Preserve NUL terminator byte
  if (parsed.bytes > parsed.text.length) {
    coverage.push({
      protocol: 'smpp',
      offset: cursor + parsed.text.length,
      length: parsed.bytes - parsed.text.length,
      status: 'covered',
    })
  }
  coverage.push({
    protocol: 'smpp-addr',
    offset: cursor,
    length: parsed.text.length,
    status: 'covered',
  })
  return cursor + parsed.bytes
}

function readMapCOctet(
  buffer: Uint8Array,
  cursor: number,
  end: number,
  maxLen: number,
  category: IdentityCategory,
  domain: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  prefix?: string,
): number {
  void domain
  const parsed = readCOctet(buffer, cursor, end, maxLen)
  if (parsed.bytes === 0) return cursor
  if (parsed.text.length > 0) {
    mapAscii(
      buffer,
      cursor,
      parsed.text.length,
      category,
      collector,
      mapping,
      intents,
      packetIndex,
      prefix,
    )
    coverage.push({
      protocol: 'smpp-id',
      offset: cursor,
      length: parsed.text.length,
      status: 'covered',
    })
  }
  if (parsed.bytes > parsed.text.length) {
    coverage.push({
      protocol: 'smpp',
      offset: cursor + parsed.text.length,
      length: parsed.bytes - parsed.text.length,
      status: 'covered',
    })
  }
  return cursor + parsed.bytes
}

function readMaskCOctet(
  buffer: Uint8Array,
  cursor: number,
  end: number,
  maxLen: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): number {
  const parsed = readCOctet(buffer, cursor, end, maxLen)
  if (parsed.bytes === 0) return cursor
  if (parsed.text.length > 0) {
    maskRange(collector, intents, packetIndex, cursor, parsed.text.length, 'smpp-password')
    coverage.push({
      protocol: 'smpp-auth',
      offset: cursor,
      length: parsed.text.length,
      status: 'redacted',
    })
    issues.push('smpp-password-masked')
  }
  if (parsed.bytes > parsed.text.length) {
    coverage.push({
      protocol: 'smpp',
      offset: cursor + parsed.text.length,
      length: parsed.bytes - parsed.text.length,
      status: 'covered',
    })
  }
  return cursor + parsed.bytes
}

function readCOctet(
  buffer: Uint8Array,
  offset: number,
  end: number,
  maxLen: number,
): { text: string; bytes: number } {
  if (offset >= end) return { text: '', bytes: 0 }
  let i = 0
  let text = ''
  while (offset + i < end && i < maxLen) {
    const b = buffer[offset + i]!
    if (b === 0) return { text, bytes: i + 1 }
    if (b < 0x20 || b > 0x7e) {
      // Non-ASCII — consume until NUL or max as opaque length
      while (offset + i < end && i < maxLen && buffer[offset + i] !== 0) i++
      const hasNul = offset + i < end && buffer[offset + i] === 0
      return { text: '', bytes: i + (hasNul ? 1 : 0) }
    }
    text += String.fromCharCode(b)
    i++
  }
  // No NUL within max — treat as fixed field (still length-preserving)
  return { text, bytes: i }
}

function isPhoneLike(s: string): boolean {
  return /^\+?\d{3,20}$/.test(s)
}

function mapBytesAsOpaque(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  prefix: string,
): void {
  let ascii = true
  let text = ''
  for (let i = 0; i < length; i++) {
    const c = buffer[offset + i]!
    if (c === 0) {
      text = text // stop
      break
    }
    if (c < 0x20 || c > 0x7e) {
      ascii = false
      break
    }
    text += String.fromCharCode(c)
  }
  if (ascii && text.length > 0) {
    mapAscii(buffer, offset, text.length, 'opaque-id', collector, mapping, intents, packetIndex, prefix)
    coverage.push({ protocol: 'smpp-id', offset, length: text.length, status: 'covered' })
    if (text.length < length) {
      coverage.push({
        protocol: 'smpp',
        offset: offset + text.length,
        length: length - text.length,
        status: 'covered',
      })
    }
  } else {
    maskRange(collector, intents, packetIndex, offset, length, 'smpp-opaque')
    coverage.push({ protocol: 'smpp-id', offset, length, status: 'redacted' })
  }
}

function mapAscii(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: IdentityCategory,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  prefix?: string,
): void {
  void mapping
  void buffer
  if (length <= 0) return
  let text = ''
  for (let i = 0; i < length; i++) {
    text += String.fromCharCode(buffer[offset + i]!)
  }
  const forCanon = prefix ? `${prefix}${text}` : text
  const canon = canonicalizeIdentity(category, forCanon) ?? forCanon
  const constraint = { kind: 'text-ascii' as const, byteLength: length }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, length, constraint, text)
  try {
    collector.addDeferred(
      offset,
      length,
      ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(
            offset,
            length,
            live.aliasFor(category, canon, constraint, text),
          )
        } catch {
          return createProtocolNeutralMaskFill({
            length,
            packetIndex,
            offset,
            domain: `smpp-${category}`,
          })
        }
      },
      {
        fallbackKind: category === 'sip-phone' ? 'digits' : 'text-x',
        protocol: 'smpp',
        category,
        packetIndex,
      },
    )
  } catch {
    /* overlap */
  }
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  try {
    collector.add(offset, fill)
  } catch {
    /* overlap */
  }
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'smpp')
}

function readU32(buf: Uint8Array, o: number): number {
  return (
    ((buf[o]! << 24) | (buf[o + 1]! << 16) | (buf[o + 2]! << 8) | buf[o + 3]!)
    >>> 0
  )
}
