/**
 * T38 — IS-IS over LLC 0xFE/0xFE. System ID / hostname TLV mapped; auth TLV masked.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { maskBytes } from './common.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'

export function sanitizeIsis(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = []
  const len = data.length - offset
  // Common header after LLC: Intra-domain Routeing Protocol Discriminator (0x83) …
  if (len < 8 || data[offset] !== 0x83) {
    coverage.push({ protocol: 'isis', offset, length: len, status: 'unsupported' })
    return { coverage, lastCoveredOffset: offset }
  }

  coverage.push({ protocol: 'isis', offset, length: 8, status: 'covered' })
  // System ID often at fixed offsets depending on PDU — treat 6 bytes at offset+8 if present as opaque/mac-like
  if (len >= 14) {
    const sysId = data.subarray(offset + 8, offset + 14)
    const canon = Array.from(sysId, (b) => b.toString(16).padStart(2, '0')).join('')
    intents?.recordEntityReplacement(packetIndex, offset + 8, 'opaque-id', `isis-sys/${canon}`, 6)
    collector.addDeferred(
      offset + 8,
      6,
      ({ mapping: live }) => {
        const alias = live.map('opaque-id', `isis-sys/${canon}`)
        const hex = alias.replace(/[^0-9a-f]/gi, '').padEnd(12, '0')
        const out = new Uint8Array(6)
        for (let i = 0; i < 6; i++) {
          out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16) & 0xff
        }
        return out
      },
      { fallbackKind: 'binary-mask', protocol: 'isis', category: 'opaque-id', packetIndex },
    )
    void mapping
  }

  // TLV walk from a conservative start (after common 8 + optional fields varies).
  // Scan remaining for Auth TLV (type 10) and Hostname (137).
  let pos = offset + 8
  const end = data.length
  while (pos + 2 <= end) {
    const t = data[pos]!
    const l = data[pos + 1]!
    if (l > end - pos - 2) break
    if (t === 10) {
      // Authentication
      if (l > 0) {
        maskBytes(collector, intents, packetIndex, pos + 2, l, 'isis-auth', 'isis')
        coverage.push({ protocol: 'isis-auth', offset: pos, length: 2 + l, status: 'redacted' })
      }
    } else if (t === 137 && l > 0) {
      const nameOff = pos + 2
      const nameBytes = data.subarray(nameOff, nameOff + l)
      const name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes)
      const trimmed = name.replace(/\0+$/, '')
      if (trimmed.length > 0) {
        intents?.recordEntityReplacement(packetIndex, nameOff, 'hostname', trimmed, l)
        try {
          collector.addDeferred(nameOff, l, ({ mapping: live }) => {
            const alias = live.aliasFor(
              'hostname',
              trimmed,
              { kind: 'text-ascii', byteLength: l },
              trimmed,
            )
            return computeFixedLengthAsciiBytes(nameOff, l, alias)
          }, { fallbackKind: 'text-x', protocol: 'isis', category: 'hostname', packetIndex })
        } catch {
          /* overlap */
        }
      }
      void nameBytes
      coverage.push({ protocol: 'isis-hostname', offset: pos, length: 2 + l, status: 'covered' })
    } else if (l > 0 && (t === 128 || t === 130 || t === 135 || t === 236)) {
      // IP reachability TLVs — mask values (prefix dictionary incomplete beyond type)
      maskBytes(collector, intents, packetIndex, pos + 2, l, 'isis-reach', 'isis')
      coverage.push({ protocol: 'isis-tlv', offset: pos, length: 2 + l, status: 'redacted' })
    }
    pos += 2 + l
    if (l === 0) break
  }

  if (pos < end) {
    // Already walked; any gap before first TLV already part of header region
  }
  return { coverage, lastCoveredOffset: end }
}
