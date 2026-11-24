/**
 * T39 — X11 (TCP 6000–6063): MIT-MAGIC-COOKIE auth data mask; post-setup body mask
 * (opcodes preserved only for the first byte of each 4-unit request when length is clear).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { asciiIndexOf, maskBytes, readU16be } from './common.ts'

function u16(buf: Uint8Array, o: number, le: boolean): number {
  return le ? (buf[o]! | (buf[o + 1]! << 8)) : readU16be(buf, o)
}

export const X11_PORT_MIN = 6000
export const X11_PORT_MAX = 6063

export function isX11PortHint(srcPort: number, dstPort: number): boolean {
  return (
    (srcPort >= X11_PORT_MIN && srcPort <= X11_PORT_MAX)
    || (dstPort >= X11_PORT_MIN && dstPort <= X11_PORT_MAX)
  )
}

export function looksLikeX11Setup(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 12) return false
  const order = buffer[offset]!
  if (order !== 0x42 && order !== 0x6c) return false // 'B' or 'l'
  return true
}

export function sanitizeX11(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isX11PortHint(srcPort, dstPort)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length

  if (!looksLikeX11Setup(buffer, offset, length)) {
    // Mid-connection: mask bodies; keep first byte of each 32-bit unit as opcode when aligned.
    maskBytes(collector, intents, packetIndex, offset, length, 'x11-session', 'x11')
    coverage.push({ protocol: 'x11', offset, length, status: 'redacted' })
    issues.push('x11-session-masked')
    return { coverage, issues }
  }

  const le = buffer[offset]! === 0x6c
  // Setup: order(1) unused(1) major(2) minor(2) nameLen(2) dataLen(2) unused(2)
  const nameLen = u16(buffer, offset + 6, le)
  const dataLen = u16(buffer, offset + 8, le)
  const namePad = (4 - (nameLen % 4)) % 4
  const dataPad = (4 - (dataLen % 4)) % 4
  const setupLen = 12 + nameLen + namePad + dataLen + dataPad

  coverage.push({ protocol: 'x11', offset, length: Math.min(12, length), status: 'covered' })

  if (setupLen > length) {
    // Truncated setup — mask auth region we can see
    if (12 + nameLen <= length) {
      const authName = new TextDecoder('ascii', { fatal: false }).decode(
        buffer.subarray(offset + 12, offset + 12 + nameLen),
      )
      if (/MAGIC-COOKIE/i.test(authName) || asciiIndexOf(buffer, offset, length, 'MIT-MAGIC-COOKIE') >= 0) {
        const dataOff = offset + 12 + nameLen + namePad
        const visible = Math.min(dataLen, end - dataOff)
        if (visible > 0) {
          maskBytes(collector, intents, packetIndex, dataOff, visible, 'x11-auth', 'x11')
          coverage.push({ protocol: 'x11-auth', offset: dataOff, length: visible, status: 'redacted' })
        }
      }
    }
    maskBytes(
      collector,
      intents,
      packetIndex,
      offset + 12,
      length - 12,
      'x11-setup-trunc',
      'x11',
    )
    coverage.push({
      protocol: 'x11-body',
      offset: offset + 12,
      length: length - 12,
      status: 'redacted',
    })
    return { coverage, issues: ['x11-setup-truncated'] }
  }

  const nameOff = offset + 12
  const dataOff = nameOff + nameLen + namePad
  if (dataLen > 0) {
    maskBytes(collector, intents, packetIndex, dataOff, dataLen, 'x11-auth', 'x11')
    coverage.push({ protocol: 'x11-auth', offset: dataOff, length: dataLen, status: 'redacted' })
  } else if (nameLen > 0) {
    // No data but named auth — still sensitive negotiation
    coverage.push({ protocol: 'x11-auth-name', offset: nameOff, length: nameLen, status: 'covered' })
  }

  let pos = offset + setupLen
  if (pos < end) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'x11-body', 'x11')
    coverage.push({ protocol: 'x11-body', offset: pos, length: end - pos, status: 'redacted' })
    issues.push('x11-requests-events-masked')
  }

  coverage.push({ protocol: 'x11', offset, length, status: 'covered' })
  return { coverage, issues }
}
