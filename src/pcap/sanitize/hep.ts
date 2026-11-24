/**
 * T35 — HEP/EEP capture encapsulation (HEPv3 + HEPv1/v2).
 * Outer chunk IPs/ports share SessionMapping with L3/L4; payload dispatched by type dictionary.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import type { PayloadTimeSession } from '../kernel/payloadTimeCodec'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { PatchCollector } from './PatchCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { sanitizeSipMessage } from './sip'
import { sanitizeRtcp } from './rtcp'
import { classifySipPayload } from '../protocols/application/sip/classify'
import type { AppLayerResult, LayerCoverage } from './types'

const HEP_PORTS = new Set([9060])

/** sipcapture vendor chunk type ids (HEPv3 / EEP). */
const CHUNK = {
  IP_FAMILY: 0x0001,
  IP_PROTO: 0x0002,
  SRC_IPV4: 0x0003,
  DST_IPV4: 0x0004,
  SRC_IPV6: 0x0005,
  DST_IPV6: 0x0006,
  SRC_PORT: 0x0007,
  DST_PORT: 0x0008,
  TS_SEC: 0x0009,
  TS_USEC: 0x000a,
  PROTO_TYPE: 0x000b,
  CAPT_ID: 0x000c,
  AUTH_KEY: 0x000e,
  PAYLOAD: 0x000f,
  CAPT_NAME: 0x0011,
  CORRELATION: 0x0012,
} as const

/** Payload-type dictionary (not IP protocol). SIPCAPTURE HEP/EEP. */
const PAYLOAD_SIP = 0x01
const PAYLOAD_SDP = 0x03
const PAYLOAD_RTCP = 0x05

export function isHepPortHint(src: number, dst: number): boolean {
  return HEP_PORTS.has(src) || HEP_PORTS.has(dst)
}

export function looksLikeHep3(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 6) return false
  return (
    data[offset] === 0x48
    && data[offset + 1] === 0x45
    && data[offset + 2] === 0x50
    && data[offset + 3] === 0x33
  )
}

export function looksLikeHepLegacy(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const ver = data[offset]!
  if (ver !== 1 && ver !== 2) return false
  const hdrLen = data[offset + 1]!
  if (hdrLen < 8 || hdrLen > length) return false
  const family = data[offset + 2]!
  return family === 2 || family === 10 // AF_INET / AF_INET6
}

export function looksLikeHep(data: Uint8Array, offset: number, length: number): boolean {
  return looksLikeHep3(data, offset, length) || looksLikeHepLegacy(data, offset, length)
}

export function sanitizeHep(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime?: PayloadTimeSession,
  mediaFlowIndex?: MediaFlowIndex,
  transport: 'udp' | 'tcp' = 'udp',
): AppLayerResult | null {
  if (looksLikeHep3(buffer, offset, length)) {
    return sanitizeHep3(
      buffer,
      offset,
      length,
      collector,
      mapping,
      intents,
      packetIndex,
      payloadTime,
      mediaFlowIndex,
      transport,
    )
  }
  if (looksLikeHepLegacy(buffer, offset, length)) {
    return sanitizeHepLegacy(
      buffer,
      offset,
      length,
      collector,
      mapping,
      intents,
      packetIndex,
      payloadTime,
      mediaFlowIndex,
      transport,
    )
  }
  return null
}

function sanitizeHep3(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  mediaFlowIndex: MediaFlowIndex | undefined,
  transport: 'udp' | 'tcp',
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const totalLen = ((buffer[offset + 4]! << 8) | buffer[offset + 5]!) >>> 0
  if (totalLen < 6 || totalLen > length) {
    maskSpan(buffer, offset, length, collector, packetIndex, 'hep-malformed')
    coverage.push({ protocol: 'hep', offset, length, status: 'malformed' })
    return { coverage, issues: ['hep-length'] }
  }

  coverage.push({ protocol: 'hep', offset, length: 6, status: 'covered' })

  let ipFamily = 0
  let ipProto = 17 // default UDP
  let payloadType = 0
  let payloadOff = -1
  let payloadLen = 0
  let tsSecOff = -1
  let tsUsecOff = -1

  let cursor = offset + 6
  const end = offset + totalLen
  while (cursor + 6 <= end) {
    const vendor = ((buffer[cursor]! << 8) | buffer[cursor + 1]!) >>> 0
    const type = ((buffer[cursor + 2]! << 8) | buffer[cursor + 3]!) >>> 0
    const chunkLen = ((buffer[cursor + 4]! << 8) | buffer[cursor + 5]!) >>> 0
    if (chunkLen < 6 || cursor + chunkLen > end) {
      maskSpan(buffer, cursor, end - cursor, collector, packetIndex, 'hep-chunk-tail')
      issues.push('hep-chunk-bounds')
      coverage.push({
        protocol: 'hep-chunk',
        offset: cursor,
        length: end - cursor,
        status: 'malformed',
      })
      break
    }
    const valOff = cursor + 6
    const valLen = chunkLen - 6

    if (vendor !== 0) {
      // Unknown vendor — keep framing, mask body
      if (valLen > 0) maskSpan(buffer, valOff, valLen, collector, packetIndex, `hep-v${vendor}`)
      coverage.push({
        protocol: 'hep-chunk',
        offset: cursor,
        length: chunkLen,
        status: 'heuristic',
      })
      cursor += chunkLen
      continue
    }

    switch (type) {
      case CHUNK.IP_FAMILY:
        if (valLen >= 1) ipFamily = buffer[valOff]!
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.IP_PROTO:
        if (valLen >= 1) ipProto = buffer[valOff]!
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.SRC_IPV4:
      case CHUNK.DST_IPV4:
        if (valLen === 4) mapIpv4(buffer, valOff, collector, mapping, intents, packetIndex)
        else if (valLen > 0) maskSpan(buffer, valOff, valLen, collector, packetIndex, 'hep-ipv4')
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.SRC_IPV6:
      case CHUNK.DST_IPV6:
        if (valLen === 16) mapIpv6(buffer, valOff, collector, mapping, intents, packetIndex)
        else if (valLen > 0) maskSpan(buffer, valOff, valLen, collector, packetIndex, 'hep-ipv6')
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.SRC_PORT:
      case CHUNK.DST_PORT:
        if (valLen === 2) {
          const port = ((buffer[valOff]! << 8) | buffer[valOff + 1]!) >>> 0
          const l4 = ipProto === 6 ? 'tcp' : 'udp'
          mapPort(buffer, valOff, port, l4, collector, mapping, intents, packetIndex)
        } else if (valLen > 0) {
          maskSpan(buffer, valOff, valLen, collector, packetIndex, 'hep-port')
        }
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.TS_SEC:
        if (valLen === 4) tsSecOff = valOff
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.TS_USEC:
        if (valLen === 4) tsUsecOff = valOff
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.PROTO_TYPE:
        if (valLen >= 1) payloadType = buffer[valOff]!
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.CAPT_ID:
        if (valLen > 0) mapOpaque(buffer, valOff, valLen, collector, mapping, intents, packetIndex, 'hep-captid')
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.AUTH_KEY:
        if (valLen > 0) maskSpan(buffer, valOff, valLen, collector, packetIndex, 'hep-auth')
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.CAPT_NAME:
        if (valLen > 0) mapOpaque(buffer, valOff, valLen, collector, mapping, intents, packetIndex, 'hep-captname')
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.CORRELATION:
        // Correlation is opaque namespace — never auto-merge with sip-call-id
        if (valLen > 0) mapOpaque(buffer, valOff, valLen, collector, mapping, intents, packetIndex, 'hep-corr')
        coverage.push({ protocol: 'hep-chunk', offset: cursor, length: chunkLen, status: 'covered' })
        break
      case CHUNK.PAYLOAD:
        payloadOff = valOff
        payloadLen = valLen
        break
      default:
        if (valLen > 0) maskSpan(buffer, valOff, valLen, collector, packetIndex, `hep-t${type}`)
        coverage.push({
          protocol: 'hep-chunk',
          offset: cursor,
          length: chunkLen,
          status: 'heuristic',
        })
        break
    }
    cursor += chunkLen
  }

  if (tsSecOff >= 0) {
    rewriteCaptureTimestamp(buffer, tsSecOff, tsUsecOff, collector, intents, packetIndex, payloadTime)
  }

  void ipFamily
  if (payloadOff >= 0 && payloadLen > 0) {
    const child = sanitizeHepPayload(
      buffer,
      payloadOff,
      payloadLen,
      payloadType,
      collector,
      mapping,
      intents,
      packetIndex,
      mediaFlowIndex,
      transport,
    )
    coverage.push(...child.coverage)
    if (child.issues) issues.push(...child.issues)
  } else if (totalLen > 6) {
    // no payload chunk — fine
  }

  if (end < offset + length) {
    // Trailing bytes beyond declared total — mask, do not claim safe padding
    maskSpan(buffer, end, offset + length - end, collector, packetIndex, 'hep-trailer')
    coverage.push({
      protocol: 'hep-trailer',
      offset: end,
      length: offset + length - end,
      status: 'heuristic',
    })
  }

  return { coverage, issues: issues.length ? issues : undefined }
}

function sanitizeHepLegacy(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  mediaFlowIndex: MediaFlowIndex | undefined,
  transport: 'udp' | 'tcp',
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const ver = buffer[offset]!
  const hdrLen = buffer[offset + 1]!
  const family = buffer[offset + 2]!
  const proto = buffer[offset + 3]!
  const sport = ((buffer[offset + 4]! << 8) | buffer[offset + 5]!) >>> 0
  const dport = ((buffer[offset + 6]! << 8) | buffer[offset + 7]!) >>> 0
  const l4 = proto === 6 ? 'tcp' : 'udp'

  coverage.push({ protocol: 'hep', offset, length: 8, status: 'covered' })
  mapPort(buffer, offset + 4, sport, l4, collector, mapping, intents, packetIndex)
  mapPort(buffer, offset + 6, dport, l4, collector, mapping, intents, packetIndex)

  let cursor = offset + 8
  if (family === 2 && cursor + 8 <= offset + length) {
    mapIpv4(buffer, cursor, collector, mapping, intents, packetIndex)
    mapIpv4(buffer, cursor + 4, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'hep-chunk', offset: cursor, length: 8, status: 'covered' })
    cursor += 8
  } else if (family === 10 && cursor + 32 <= offset + length) {
    mapIpv6(buffer, cursor, collector, mapping, intents, packetIndex)
    mapIpv6(buffer, cursor + 16, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'hep-chunk', offset: cursor, length: 32, status: 'covered' })
    cursor += 32
  }

  // HEPv2 optional vlan + captid/time (best-effort fixed layout after addresses)
  if (ver === 2 && cursor + 2 <= offset + length && hdrLen >= cursor - offset + 2) {
    // vlan id — preserve (not identity)
    cursor += 2
  }

  if (cursor + 10 <= offset + length) {
    const tsSecOff = cursor
    const tsUsecOff = cursor + 4
    const captOff = cursor + 8
    rewriteCaptureTimestamp(buffer, tsSecOff, tsUsecOff, collector, intents, packetIndex, payloadTime)
    mapOpaque(buffer, captOff, 2, collector, mapping, intents, packetIndex, 'hep-captid')
    coverage.push({ protocol: 'hep-chunk', offset: cursor, length: 10, status: 'covered' })
    cursor += 10
  }

  // Skip any remaining declared header bytes
  if (cursor < offset + hdrLen) cursor = offset + hdrLen

  const payloadOff = cursor
  const payloadLen = offset + length - cursor
  if (payloadLen > 0) {
    // Legacy HEP is almost always SIP
    const child = sanitizeHepPayload(
      buffer,
      payloadOff,
      payloadLen,
      PAYLOAD_SIP,
      collector,
      mapping,
      intents,
      packetIndex,
      mediaFlowIndex,
      transport,
    )
    coverage.push(...child.coverage)
    if (child.issues) issues.push(...child.issues)
  }

  return { coverage, issues: issues.length ? issues : undefined }
}

function sanitizeHepPayload(
  buffer: Uint8Array,
  offset: number,
  length: number,
  payloadType: number,
  collector: PatchCollector,
  mapping: MappingLike,
  _intents: IntentCollector | undefined,
  packetIndex: number,
  mediaFlowIndex: MediaFlowIndex | undefined,
  transport: 'udp' | 'tcp',
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  if (payloadType === PAYLOAD_SIP || payloadType === PAYLOAD_SDP) {
    const classification = classifySipPayload(buffer, offset, length, { portHint: true })
    if (classification.kind === 'complete') {
      mediaFlowIndex?.registerFromSipMessage(classification.message, buffer)
      const sipIssues = sanitizeSipMessage(
        buffer,
        classification.message,
        transport,
        collector,
        mapping,
      )
      coverage.push({ protocol: 'hep-payload', offset, length, status: 'covered' })
      coverage.push({
        protocol: 'sip',
        offset,
        length: classification.consumed,
        status: 'covered',
      })
      if (sipIssues.length) issues.push(...sipIssues)
      return { coverage, issues: issues.length ? issues : undefined }
    }
    // SDP-only or incomplete — fail-closed mask (do not invent SIP)
    maskSpan(buffer, offset, length, collector, packetIndex, 'hep-sip-incomplete')
    coverage.push({ protocol: 'hep-payload', offset, length, status: 'malformed' })
    issues.push('hep-payload-incomplete')
    return { coverage, issues }
  }

  if (payloadType === PAYLOAD_RTCP) {
    // Binary RTCP: V=2 in first byte; else producer JSON → mask (never blind RTCP parse)
    const v = length > 0 ? (buffer[offset]! >> 6) & 0x03 : 0
    if (v === 2) {
      const ok = sanitizeRtcp(buffer, offset, length, collector, mapping, undefined, packetIndex)
      coverage.push({
        protocol: 'hep-payload',
        offset,
        length,
        status: ok ? 'covered' : 'heuristic',
      })
      if (!ok) {
        maskSpan(buffer, offset, length, collector, packetIndex, 'hep-rtcp-fail')
        issues.push('hep-rtcp')
      }
      return { coverage, issues: issues.length ? issues : undefined }
    }
    maskSpan(buffer, offset, length, collector, packetIndex, 'hep-rtcp-json')
    coverage.push({ protocol: 'hep-payload', offset, length, status: 'heuristic' })
    return { coverage, issues: ['hep-rtcp-nonbinary'] }
  }

  // Unknown / compressed / other payload types — mask body, keep type chunk elsewhere
  maskSpan(buffer, offset, length, collector, packetIndex, `hep-pt${payloadType}`)
  coverage.push({ protocol: 'hep-payload', offset, length, status: 'unsupported' })
  return { coverage, issues: [`hep-payload-type-${payloadType}`] }
}

function rewriteCaptureTimestamp(
  buffer: Uint8Array,
  secOff: number,
  usecOff: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
): void {
  const sec =
    ((buffer[secOff]! << 24)
      | (buffer[secOff + 1]! << 16)
      | (buffer[secOff + 2]! << 8)
      | buffer[secOff + 3]!) >>> 0
  const usec =
    usecOff >= 0
      ? ((buffer[usecOff]! << 24)
        | (buffer[usecOff + 1]! << 16)
        | (buffer[usecOff + 2]! << 8)
        | buffer[usecOff + 3]!) >>> 0
      : 0

  if (!payloadTime?.isBound) {
    maskSpan(buffer, secOff, 4, collector, packetIndex, 'hep-ts-sec')
    if (usecOff >= 0) maskSpan(buffer, usecOff, 4, collector, packetIndex, 'hep-ts-usec')
    return
  }

  const epochMs = sec * 1000 + Math.floor(usec / 1000)
  intents?.recordEntityReplacement(packetIndex, secOff, 'timestamp', String(sec), 4)
  collector.addDeferred(secOff, 4, () => {
    const shiftedMs = payloadTime.shiftAbsoluteEpochMs(epochMs)
    if (shiftedMs == null) {
      return createProtocolNeutralMaskFill({
        length: 4,
        packetIndex,
        offset: secOff,
        domain: 'hep-ts',
      })
    }
    const shiftedSec = Math.floor(shiftedMs / 1000) >>> 0
    return new Uint8Array([
      (shiftedSec >>> 24) & 0xff,
      (shiftedSec >>> 16) & 0xff,
      (shiftedSec >>> 8) & 0xff,
      shiftedSec & 0xff,
    ])
  }, { fallbackKind: 'binary-mask', protocol: 'hep', category: 'timestamp', packetIndex })

  if (usecOff >= 0) {
    collector.addDeferred(usecOff, 4, () => {
      const shiftedMs = payloadTime.shiftAbsoluteEpochMs(epochMs)
      if (shiftedMs == null) {
        return createProtocolNeutralMaskFill({
          length: 4,
          packetIndex,
          offset: usecOff,
          domain: 'hep-ts-usec',
        })
      }
      const shiftedUsec = Math.floor((shiftedMs % 1000) * 1000) >>> 0
      return new Uint8Array([
        (shiftedUsec >>> 24) & 0xff,
        (shiftedUsec >>> 16) & 0xff,
        (shiftedUsec >>> 8) & 0xff,
        shiftedUsec & 0xff,
      ])
    }, { fallbackKind: 'binary-mask', protocol: 'hep', category: 'timestamp', packetIndex })
  }
}

function mapIpv4(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const text = `${buffer[abs]!}.${buffer[abs + 1]!}.${buffer[abs + 2]!}.${buffer[abs + 3]!}`
  if (text === '0.0.0.0' || text === '255.255.255.255') return
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv4', text, 4)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    const mapped = live.map('ipv4', text)
    return new Uint8Array(mapped.split('.').map(Number))
  }, { fallbackKind: 'binary-mask', protocol: 'hep', category: 'ipv4', packetIndex })
  void mapping
}

function mapIpv6(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const parts: string[] = []
  for (let i = 0; i < 16; i += 2) {
    parts.push(((buffer[abs + i]! << 8) | buffer[abs + i + 1]!).toString(16))
  }
  const text = parts.join(':')
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv6', text, 16)
  collector.addDeferred(abs, 16, ({ mapping: live }) => {
    const mapped = live.map('ipv6', text)
    const fill = createProtocolNeutralMaskFill({
      length: 16,
      packetIndex,
      offset: abs,
      domain: 'hep-ipv6',
    })
    const hextets = mapped.split(':')
    if (hextets.length !== 8) return fill
    const out = new Uint8Array(16)
    for (let i = 0; i < 8; i++) {
      const v = Number.parseInt(hextets[i]!, 16)
      if (!Number.isFinite(v)) return fill
      out[i * 2] = (v >> 8) & 0xff
      out[i * 2 + 1] = v & 0xff
    }
    return out
  }, { fallbackKind: 'binary-mask', protocol: 'hep', category: 'ipv6', packetIndex })
  void mapping
}

function mapPort(
  buffer: Uint8Array,
  abs: number,
  port: number,
  proto: 'tcp' | 'udp',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const canonical = `${proto}/${port}`
  intents?.recordEntityReplacement(packetIndex, abs, 'port', canonical, 2)
  collector.addDeferred(abs, 2, ({ mapping: live }) => {
    const mapped = live.map('port', canonical)
    const slash = mapped.indexOf('/')
    if (slash < 0) return null
    const mappedPort = Number.parseInt(mapped.slice(slash + 1), 10)
    if (!Number.isInteger(mappedPort) || mappedPort < 0 || mappedPort > 65535 || mappedPort === port) {
      return null
    }
    return new Uint8Array([(mappedPort >> 8) & 0xff, mappedPort & 0xff])
  }, { fallbackKind: 'binary-mask', protocol: 'hep', category: 'port', packetIndex })
  void buffer
  void mapping
}

function mapOpaque(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  const raw = new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
  const hex = Array.from(buffer.subarray(abs, abs + len))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  const canon = canonicalizeIdentity('opaque-id', hex.length >= 4 ? hex : raw) ?? hex
  const printable = /^[\x20-\x7e]+$/.test(raw)
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(
    packetIndex,
    abs,
    'opaque-id',
    canon,
    len,
    printable ? constraint : { kind: 'text-ascii', byteLength: len },
    raw,
  )
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      if (printable) {
        return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('opaque-id', canon, constraint, raw))
      }
      const alias = live.map('opaque-id', canon)
      return createProtocolNeutralMaskFill({
        length: len,
        packetIndex,
        offset: abs,
        domain: `${domain}:${alias.slice(0, 16)}`,
      })
    } catch {
      return createProtocolNeutralMaskFill({
        length: len,
        packetIndex,
        offset: abs,
        domain,
      })
    }
  }, {
    fallbackKind: printable ? 'text-x' : 'binary-mask',
    protocol: 'hep',
    category: 'opaque-id',
    packetIndex,
  })
  void mapping
}

function maskSpan(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  packetIndex: number,
  domain: string,
): void {
  if (len <= 0) return
  try {
    collector.maskRangeDeferred(abs, len, () =>
      createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain }),
    )
  } catch {
    /* overlap */
  }
  void buffer
}
