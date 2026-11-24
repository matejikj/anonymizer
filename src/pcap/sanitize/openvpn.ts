/**
 * T28 — OpenVPN baseline: session-id → scoped opaque-id; control channel TLS-like bytes via tls.ts;
 * data channel ciphertext → mask when confidentiality is not proven (R02/R09).
 * TCP transport uses a 2-byte big-endian length prefix before each datagram (same opcode layout as UDP).
 */

import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { PatchCollector } from './PatchCollector.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from './maskFill.ts'
import { looksLikeTlsRecord } from './mediaPolicy.ts'
import { sanitizeTls } from './tls.ts'

export const OPENVPN_UDP_PORT = 1194

const OPENVPN_MAX_FRAME = 65_535
const OPENVPN_MAX_FRAMES_PER_SEGMENT = 32

/** opcode = top 5 bits of first byte (OpenVPN wire format). */
const P_DATA_V1 = 6
const P_DATA_V2 = 9
const P_CONTROL_HARD_RESET_CLIENT_V2 = 7
const P_CONTROL_HARD_RESET_SERVER_V2 = 8
const P_CONTROL_SOFT_RESET_V1 = 3
const P_CONTROL_V1 = 4

export type OpenVpnTransport = 'udp' | 'tcp'

export function isOpenVpnPortHint(src: number, dst: number): boolean {
  return src === OPENVPN_UDP_PORT || dst === OPENVPN_UDP_PORT
}

function readTcpFrameLen(buffer: Uint8Array, offset: number): number {
  return (buffer[offset]! << 8) | buffer[offset + 1]!
}

/**
 * Content-probe shape (no port): hard-reset only.
 * Soft-reset opcode 3 collides with NTP (0x1c); DATA_V2/0x48 collides with GTPv2.
 */
export function looksLikeOpenVpn(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 16) return false
  const opKey = buffer[offset]!
  const gtpVer = (opKey >> 5) & 0x7
  if (gtpVer === 1 || gtpVer === 2) return false
  const opcode = opKey >> 3
  if (opcode !== P_CONTROL_HARD_RESET_CLIENT_V2 && opcode !== P_CONTROL_HARD_RESET_SERVER_V2) {
    return false
  }
  return length >= 1 + 8 + 4
}

/**
 * TCP length-prefixed OpenVPN (content probe, no port): complete first frame + hard-reset inner.
 */
export function looksLikeOpenVpnTcp(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 2 + 16) return false
  const frameLen = readTcpFrameLen(buffer, offset)
  if (frameLen < 16 || frameLen > OPENVPN_MAX_FRAME) return false
  if (offset + 2 + frameLen > length) return false
  return looksLikeOpenVpn(buffer, offset + 2, frameLen)
}

/**
 * Port-hinted shape (UDP/TCP 1194): allow data/control opcodes.
 * Do not apply GTP version rejection here — DATA_V1 (opcode 6 → 0x30) collides with
 * GTPv1 version bits, but GTP never uses port 1194.
 */
function looksLikeOpenVpnOnPort(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 16) return false
  const opcode = buffer[offset]! >> 3
  if (opcode < 1 || opcode > 9) return false
  return length >= 1 + 8 + 4
}

function looksLikeOpenVpnTcpOnPort(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 2 + 16) return false
  const frameLen = readTcpFrameLen(buffer, offset)
  if (frameLen < 16 || frameLen > OPENVPN_MAX_FRAME) return false
  const innerOff = offset + 2
  const innerAvail = length - 2
  if (frameLen <= innerAvail) {
    return looksLikeOpenVpnOnPort(buffer, innerOff, frameLen)
  }
  // Incomplete first frame on port — opcode in first byte of inner still a hint.
  return looksLikeOpenVpnOnPort(buffer, innerOff, innerAvail)
}

export function sanitizeOpenVpn(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  transport: OpenVpnTransport = 'udp',
): AppLayerResult | null {
  const onPort = isOpenVpnPortHint(srcPort, dstPort)
  if (transport === 'tcp') {
    if (!onPort && !looksLikeOpenVpnTcp(buffer, offset, length)) return null
    if (onPort ? !looksLikeOpenVpnTcpOnPort(buffer, offset, length) : !looksLikeOpenVpnTcp(buffer, offset, length)) {
      return null
    }
    return sanitizeOpenVpnTcpSegment(
      buffer,
      offset,
      length,
      srcPort,
      dstPort,
      collector,
      mapping,
      intents,
      packetIndex,
    )
  }

  if (!onPort && !looksLikeOpenVpn(buffer, offset, length)) return null
  if (onPort ? !looksLikeOpenVpnOnPort(buffer, offset, length) : !looksLikeOpenVpn(buffer, offset, length)) {
    return null
  }

  return sanitizeOpenVpnDatagram(
    buffer,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
  )
}

function sanitizeOpenVpnTcpSegment(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let pos = offset
  const end = offset + length
  let frames = 0

  while (pos + 2 <= end && frames < OPENVPN_MAX_FRAMES_PER_SEGMENT) {
    frames++
    const lenOff = pos
    const frameLen = readTcpFrameLen(buffer, pos)
    pos += 2
    coverage.push({ protocol: 'openvpn-tcp-framing', offset: lenOff, length: 2, status: 'covered' })

    if (frameLen < 16 || frameLen > OPENVPN_MAX_FRAME) {
      const tail = end - lenOff
      maskRange(collector, intents, packetIndex, lenOff, tail, 'openvpn-tcp-bad-len')
      coverage.push({ protocol: 'openvpn-tcp', offset: lenOff, length: tail, status: 'malformed' })
      issues.push('openvpn-tcp-bad-frame-length')
      break
    }

    if (pos + frameLen > end) {
      const tail = end - lenOff
      maskRange(collector, intents, packetIndex, lenOff, tail, 'openvpn-tcp-partial')
      coverage.push({
        protocol: 'openvpn-tcp',
        offset: lenOff,
        length: tail,
        status: 'requires-reassembly',
      })
      issues.push('openvpn-tcp-requires-reassembly')
      break
    }

    const inner = sanitizeOpenVpnDatagram(
      buffer,
      pos,
      frameLen,
      collector,
      mapping,
      intents,
      packetIndex,
    )
    coverage.push(...inner.coverage)
    if (inner.issues) issues.push(...inner.issues)
    pos += frameLen
  }

  if (pos < end && frames >= OPENVPN_MAX_FRAMES_PER_SEGMENT) {
    const tail = end - pos
    maskRange(collector, intents, packetIndex, pos, tail, 'openvpn-tcp-tail')
    coverage.push({ protocol: 'openvpn-tcp', offset: pos, length: tail, status: 'malformed' })
    issues.push('openvpn-tcp-frame-limit')
  }

  void srcPort
  void dstPort
  return { coverage, issues: issues.length ? issues : undefined }
}

function sanitizeOpenVpnDatagram(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const opKey = buffer[offset]!
  const opcode = opKey >> 3
  coverage.push({ protocol: 'openvpn', offset, length: 1, status: 'covered' })

  const sessionOff = offset + 1
  mapSessionId(buffer, sessionOff, 8, collector, mapping, intents, packetIndex, coverage)

  const payloadOff = sessionOff + 8 + 4
  const payloadLen = offset + length - payloadOff
  if (payloadLen <= 0) {
    return { coverage, issues: ['openvpn-no-payload'] }
  }

  const isData = opcode === P_DATA_V1 || opcode === P_DATA_V2
  if (isData) {
    // Opcode alone is not proof of negotiated AEAD confidentiality — mask payload.
    maskRange(collector, intents, packetIndex, payloadOff, payloadLen, 'openvpn-data-unproven')
    coverage.push({
      protocol: 'openvpn-data',
      offset: payloadOff,
      length: payloadLen,
      status: 'redacted',
    })
    return { coverage, issues: ['openvpn-data-unproven-confidentiality'] }
  }

  if (
    opcode === P_CONTROL_V1
    || opcode === P_CONTROL_SOFT_RESET_V1
    || opcode === P_CONTROL_HARD_RESET_CLIENT_V2
    || opcode === P_CONTROL_HARD_RESET_SERVER_V2
  ) {
    if (looksLikeTlsRecord(buffer, payloadOff, payloadLen)) {
      const tls = sanitizeTls(buffer, payloadOff, payloadLen, collector, mapping, intents, packetIndex)
      if (tls) {
        coverage.push(...tls.coverage.map((c) => ({ ...c, protocol: `openvpn-${c.protocol}` })))
        if (tls.issues) issues.push(...tls.issues.map((i) => `openvpn-${i}`))
        return { coverage, issues: issues.length ? issues : undefined }
      }
    }
    maskRange(collector, intents, packetIndex, payloadOff, payloadLen, 'openvpn-control')
    coverage.push({
      protocol: 'openvpn-control',
      offset: payloadOff,
      length: payloadLen,
      status: 'redacted',
    })
    issues.push('openvpn-control-masked')
    return { coverage, issues }
  }

  maskRange(collector, intents, packetIndex, payloadOff, payloadLen, 'openvpn-unknown-op')
  coverage.push({
    protocol: 'openvpn-unknown',
    offset: payloadOff,
    length: payloadLen,
    status: 'redacted',
  })
  issues.push(`openvpn-unknown-opcode:${opcode}`)
  return { coverage, issues }
}

function mapSessionId(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  let hex = ''
  for (let i = 0; i < len; i++) hex += buffer[abs + i]!.toString(16).padStart(2, '0')
  const canon = canonicalizeIdentity('opaque-id', `openvpn-sid:${hex}`) ?? `openvpn-sid:${hex}`
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const alias = live.map('opaque-id', canon)
      const out = new Uint8Array(len)
      for (let i = 0; i < len; i++) {
        const pair = alias.slice(i * 2, i * 2 + 2)
        const v = Number.parseInt(pair, 16)
        out[i] = Number.isFinite(v) ? v & 0xff : 0xaa
      }
      return out
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'openvpn-sid' })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'openvpn', category: 'opaque-id', packetIndex })
  coverage.push({ protocol: 'openvpn-session', offset: abs, length: len, status: 'covered' })
  void mapping
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  abs: number,
  len: number,
  domain: string,
): void {
  if (len <= 0) return
  try {
    collector.maskRangeDeferred(abs, len, () =>
      createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain }),
    )
    intents?.recordMaskRange(packetIndex, abs, len, domain, 'openvpn')
  } catch {
    /* overlap */
  }
}
