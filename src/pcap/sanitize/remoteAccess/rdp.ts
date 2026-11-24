/**
 * T39 — RDP (TCP 3389): TPKT/X.224 Cookie mstshash → user-id; negotiation preserve;
 * standard RDP security / unknown body → opaque mask (not claimed as structured Client Info).
 * TLS/CredSSP on the same port is handled by the TLS sanitizer (runs first).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { asciiIndexOf, mapAsciiIdentity, maskBytes, readU16be } from './common.ts'

export const RDP_TCP_PORT = 3389
export const RDP_UDP_PORT = 3389

const COOKIE_PREFIX = 'Cookie: mstshash='
const ROUTING_COOKIE_PREFIX = 'Cookie: msts='

export function isRdpPortHint(srcPort: number, dstPort: number): boolean {
  return srcPort === RDP_TCP_PORT || dstPort === RDP_TCP_PORT
}

export function looksLikeRdp(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 7) return false
  if (buffer[offset] !== 3) return false
  const code = buffer[offset + 5]!
  if ((code & 0xf0) === 0xe0 || (code & 0xf0) === 0xd0 || code === 0xf0 || code === 0x80) {
    return true
  }
  return asciiIndexOf(buffer, offset, Math.min(length, 256), 'Cookie: mstshash=') >= 0
}

export function sanitizeRdp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isRdpPortHint(srcPort, dstPort) && !looksLikeRdp(buffer, offset, length)) return null
  if (!looksLikeRdp(buffer, offset, length)) {
    maskBytes(collector, intents, packetIndex, offset, length, 'rdp-unknown', 'rdp')
    return {
      coverage: [{ protocol: 'rdp', offset, length, status: 'redacted' }],
      issues: ['rdp-non-tpkt-masked'],
    }
  }

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length

  coverage.push({ protocol: 'rdp', offset, length: Math.min(7, length), status: 'covered' })

  const cookieAt = asciiIndexOf(buffer, offset, length, COOKIE_PREFIX)
  if (cookieAt >= 0) {
    const userStart = cookieAt + COOKIE_PREFIX.length
    let userEnd = userStart
    while (userEnd < end) {
      const b = buffer[userEnd]!
      if (b === 0x0d || b === 0x0a || b === 0x3b || b === 0x00) break
      userEnd++
    }
    if (userEnd > userStart) {
      mapAsciiIdentity(
        buffer,
        userStart,
        userEnd - userStart,
        'user-id',
        collector,
        mapping,
        intents,
        packetIndex,
        'rdp',
      )
      coverage.push({
        protocol: 'rdp-cookie',
        offset: cookieAt,
        length: userEnd - cookieAt,
        status: 'covered',
      })
    }
  }

  const routeAt = asciiIndexOf(buffer, offset, length, ROUTING_COOKIE_PREFIX)
  if (routeAt >= 0) {
    let routeEnd = routeAt + ROUTING_COOKIE_PREFIX.length
    while (routeEnd < end) {
      const b = buffer[routeEnd]!
      if (b === 0x0d || b === 0x0a || b === 0x00) break
      routeEnd++
    }
    const secretOff = routeAt + ROUTING_COOKIE_PREFIX.length
    if (routeEnd > secretOff) {
      maskBytes(
        collector,
        intents,
        packetIndex,
        secretOff,
        routeEnd - secretOff,
        'rdp-routing-cookie',
        'rdp',
      )
      coverage.push({
        protocol: 'rdp-cookie',
        offset: routeAt,
        length: routeEnd - routeAt,
        status: 'redacted',
      })
    }
  }

  // Preserve RDP_NEG_* TLVs when present in the CR.
  let scan = offset + 11
  while (scan + 8 <= end) {
    const t = buffer[scan]!
    const negLen = readU16be(buffer, scan + 2)
    if ((t === 0x01 || t === 0x02 || t === 0x03) && negLen === 8) {
      coverage.push({ protocol: 'rdp-negotiation', offset: scan, length: 8, status: 'covered' })
      scan += 8
      continue
    }
    scan++
    if (scan > offset + 128) break
  }

  // Non-CR TPKT (DT) — opaque weak security / MCS body.
  const code = buffer[offset + 5]!
  if (code === 0xf0 || ((code & 0xf0) !== 0xe0 && (code & 0xf0) !== 0xd0)) {
    const bodyOff = offset + 7
    if (bodyOff < end) {
      maskBytes(collector, intents, packetIndex, bodyOff, end - bodyOff, 'rdp-body', 'rdp')
      coverage.push({
        protocol: 'rdp-body',
        offset: bodyOff,
        length: end - bodyOff,
        status: 'redacted',
      })
      issues.push('rdp-opaque-security-masked')
    }
  }

  // Contiguous app coverage so CF-09 export boundary does not mask-in-place over cookies.
  coverage.push({ protocol: 'rdp', offset, length, status: 'covered' })

  return { coverage, issues }
}
