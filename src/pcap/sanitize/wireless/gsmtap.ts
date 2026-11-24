/**
 * T40 — GSMTAP (UDP 4729): Osmocom radio tap wrapper.
 * Header (type/ARFCN/signal/timeslot) preserve; payload identify + mask
 * (`unsupported:gsmtap-<type>`), except LTE NAS → T59 child.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { maskBytes, readU16le } from './common.ts'
import { looksLikeNas, sanitizeNas } from '../nas.ts'

export const GSMTAP_UDP_PORT = 4729

/** Osmocom GSMTAP type names (subset). */
const GSMTAP_TYPE_NAME: Record<number, string> = {
  0x01: 'um',
  0x02: 'abisc',
  0x03: 'umts-rlc-mac',
  0x04: 'umts-rrc',
  0x05: 'sim',
  0x06: 'tetra-i1',
  0x07: 'tetra-i1-burst',
  0x08: 'wmmx',
  0x09: 'e1-t1',
  0x0a: 'gmr1-um',
  0x0c: 'lte-rrc',
  0x0d: 'lte-mac',
  0x0e: 'lte-mac-framed',
  0x0f: 'lte-nas',
  0x12: 'lte-mac-ul',
  0x13: 'lte-mac-dl',
}

export function isGsmtapPortHint(src: number, dst: number): boolean {
  return src === GSMTAP_UDP_PORT || dst === GSMTAP_UDP_PORT
}

export function looksLikeGsmtap(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 16) return false
  const ver = buffer[offset]!
  return ver === 0x02 || ver === 0x03
}

export function sanitizeGsmtap(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
  mapping?: MappingLike,
): AppLayerResult | null {
  if (!isGsmtapPortHint(srcPort, dstPort) && !looksLikeGsmtap(buffer, offset, length)) return null
  if (!looksLikeGsmtap(buffer, offset, length)) {
    maskBytes(collector, intents, packetIndex, offset, length, 'gsmtap-unknown', 'gsmtap')
    return {
      coverage: [{ protocol: 'gsmtap', offset, length, status: 'redacted' }],
      issues: ['gsmtap-non-header'],
    }
  }

  const ver = buffer[offset]!
  const hdrLenWords = buffer[offset + 1]!
  const hdrLen = ver >= 3 ? hdrLenWords * 4 : 16
  const type = buffer[offset + 2]!
  const typeName = GSMTAP_TYPE_NAME[type] ?? `type-${type}`
  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []

  const headerBytes = Math.min(hdrLen, length)
  coverage.push({ protocol: 'gsmtap', offset, length: headerBytes, status: 'covered' })
  // ARFCN / signal / timeslot live in header — preserve (localization policy noted in docs)
  void readU16le

  if (length > headerBytes) {
    const payOff = offset + headerBytes
    const payLen = length - headerBytes
    // T59 — LTE NAS payload → structured NAS child when recognizable
    if (type === 0x0f && mapping && looksLikeNas(buffer, payOff, payLen)) {
      const nas = sanitizeNas(buffer, payOff, payLen, collector, mapping, intents, packetIndex)
      if (nas) {
        coverage.push(...nas.coverage)
        if (nas.issues) issues.push(...nas.issues)
      } else {
        maskBytes(collector, intents, packetIndex, payOff, payLen, 'gsmtap-lte-nas', 'gsmtap')
        coverage.push({
          protocol: 'unsupported:gsmtap-lte-nas',
          offset: payOff,
          length: payLen,
          status: 'redacted',
        })
      }
    } else {
      maskBytes(collector, intents, packetIndex, payOff, payLen, `gsmtap-${typeName}`, 'gsmtap')
      coverage.push({
        protocol: `unsupported:gsmtap-${typeName}`,
        offset: payOff,
        length: payLen,
        status: 'redacted',
      })
      issues.push(`gsmtap-payload-masked:${typeName}`)
    }
  }

  coverage.push({ protocol: 'gsmtap', offset, length, status: 'covered' })
  return { coverage, issues }
}
