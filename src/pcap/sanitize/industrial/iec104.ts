/**
 * T30 — IEC 60870-5-104 (TCP 2404): APCI preserve; CA/IOA opaque map; process values mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { maskBytes } from './common.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'

export const IEC104_TCP_PORT = 2404

export function isIec104PortHint(src: number, dst: number): boolean {
  return src === IEC104_TCP_PORT || dst === IEC104_TCP_PORT
}

export function looksLikeIec104(buffer: Uint8Array, offset: number, length: number): boolean {
  return length >= 2 && buffer[offset] === 0x68
}

function aliasOpaqueBytes(
  mapping: MappingLike,
  bytes: Uint8Array,
  scope: string,
): Uint8Array {
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
  const canon = canonicalizeIdentity('opaque-id', `${scope}/${hex}`) ?? `${scope}/${hex}`
  const alias = mapping.aliasFor(
    'opaque-id',
    canon,
    { kind: 'text-ascii', byteLength: Math.max(4, hex.length) },
    hex,
  )
  let v = 0
  for (let i = 0; i < alias.length; i++) v = (v * 33 + alias.charCodeAt(i)!) >>> 0
  const out = new Uint8Array(bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    out[i] = (v + i * 17) & 0xff
  }
  // Avoid all-zero / all-ff when original wasn't sentinel
  if (out.every((b) => b === 0)) out[0] = 1
  return out
}

export function sanitizeIec104(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  _highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isIec104PortHint(srcPort, dstPort) && !looksLikeIec104(buffer, offset, length)) {
    return null
  }

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos + 2 <= end) {
    if (buffer[pos] !== 0x68) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'iec104-desync', 'iec104')
      coverage.push({
        protocol: 'iec104-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('iec104-frame-desync')
      break
    }
    const apduLen = buffer[pos + 1]!
    if (apduLen < 4 || pos + 2 + apduLen > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'iec104-desync', 'iec104')
      coverage.push({
        protocol: 'iec104-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      break
    }
    coverage.push({ protocol: 'iec104', offset: pos, length: 6, status: 'covered' })
    const ctrl = buffer[pos + 2]!
    const isUorS = (ctrl & 0x01) !== 0
    if (isUorS || apduLen === 4) {
      coverage.push({
        protocol: 'iec104',
        offset: pos + 2,
        length: apduLen,
        status: 'covered',
      })
    } else {
      const asduOff = pos + 6
      const asduLen = apduLen - 4
      if (asduLen >= 6) {
        // type + VSQ preserve
        coverage.push({ protocol: 'iec104', offset: asduOff, length: 2, status: 'covered' })
        const useCot = asduLen >= 9 ? 2 : 1
        coverage.push({
          protocol: 'iec104',
          offset: asduOff + 2,
          length: useCot,
          status: 'covered',
        })
        let p = asduOff + 2 + useCot
        const caLen = asduLen - (p - asduOff) >= 5 ? 2 : 1
        if (p + caLen <= asduOff + asduLen) {
          const ca = buffer.subarray(p, p + caLen)
          const mapped = aliasOpaqueBytes(mapping, ca, 'iec104-ca')
          try {
            collector.add(p, mapped)
          } catch {
            /* overlap */
          }
          coverage.push({ protocol: 'iec104-ca', offset: p, length: caLen, status: 'covered' })
          p += caLen
        }
        const vsq = buffer[asduOff + 1]!
        const sq = (vsq >> 7) & 1
        const objCount = vsq & 0x7f
        const ioaFieldLen = 3
        if (objCount === 0) {
          issues.push('iec104-vsq-zero')
        } else {
          const ioaSlots = sq === 1 ? 1 : objCount
          for (let o = 0; o < ioaSlots; o++) {
            if (p + ioaFieldLen > asduOff + asduLen) {
              issues.push('iec104-ioa-truncated')
              break
            }
            const ioa = buffer.subarray(p, p + ioaFieldLen)
            const mapped = aliasOpaqueBytes(mapping, ioa, 'iec104-ioa')
            try {
              collector.add(p, mapped)
            } catch {
              /* overlap */
            }
            coverage.push({
              protocol: 'iec104-ioa',
              offset: p,
              length: ioaFieldLen,
              status: 'covered',
            })
            p += ioaFieldLen
          }
          if (sq === 1 && objCount > 1) {
            issues.push('iec104-sq-multi-object')
          }
        }
        if (p < asduOff + asduLen) {
          maskBytes(
            collector,
            intents,
            packetIndex,
            p,
            asduOff + asduLen - p,
            'iec104-values',
            'iec104',
          )
          coverage.push({
            protocol: 'iec104-values',
            offset: p,
            length: asduOff + asduLen - p,
            status: 'redacted',
          })
          issues.push('iec104-process-values-masked')
        }
      } else if (asduLen > 0) {
        maskBytes(collector, intents, packetIndex, asduOff, asduLen, 'iec104-asdu', 'iec104')
        coverage.push({
          protocol: 'iec104-body',
          offset: asduOff,
          length: asduLen,
          status: 'redacted',
        })
      }
    }

    pos += 2 + apduLen
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'iec104-session', 'iec104')
    coverage.push({ protocol: 'iec104', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}
