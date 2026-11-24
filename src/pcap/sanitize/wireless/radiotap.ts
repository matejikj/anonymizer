/**
 * T40 — Linux radiotap header (LINKTYPE_IEEE802_11_RADIO = 127).
 * Channel/rate/RSSI preserve; vendor namespace / GPS-bearing data mask; TSFT preserved
 * as relative timer (not Unix epoch shift in this baseline).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { maskBytes, readU16le, readU32le } from './common.ts'

export const LINKTYPE_IEEE802_11_RADIO = 127

/** Align `pos` to `n` relative to radiotap header start. */
function align(pos: number, itStart: number, n: number): number {
  const rel = pos - itStart
  const pad = (n - (rel % n)) % n
  return pos + pad
}

export function parseRadiotapHeader(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): { headerLen: number; coverage: LayerCoverage[]; issues: string[] } | null {
  if (data.length - offset < 8) return null
  if (data[offset] !== 0) return null // version
  const headerLen = readU16le(data, offset + 2)
  if (headerLen < 8 || offset + headerLen > data.length) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  coverage.push({ protocol: 'radiotap', offset, length: Math.min(8, headerLen), status: 'covered' })

  let presentOff = offset + 4
  const presentWords: number[] = []
  for (;;) {
    if (presentOff + 4 > offset + headerLen) break
    const word = readU32le(data, presentOff)
    presentWords.push(word)
    presentOff += 4
    if ((word & 0x8000_0000) === 0) break
  }

  let pos = presentOff
  const itStart = offset
  let bitIndex = 0
  for (const word of presentWords) {
    for (let b = 0; b < 32; b++) {
      if (bitIndex === 31) {
        // Ext bit — already consumed as next present word
        bitIndex++
        continue
      }
      if (((word >>> b) & 1) === 0) {
        bitIndex++
        continue
      }
      const field = bitIndex
      bitIndex++
      // Field sizes / alignments (Linux radiotap)
      const spec = RADIOTAP_FIELD[field]
      if (!spec) {
        // Unknown present bit — cannot safely skip; mask remainder of radiotap body
        if (pos < offset + headerLen) {
          maskBytes(
            collector,
            intents,
            packetIndex,
            pos,
            offset + headerLen - pos,
            'radiotap-unknown',
            'radiotap',
          )
          coverage.push({
            protocol: 'radiotap-vendor',
            offset: pos,
            length: offset + headerLen - pos,
            status: 'redacted',
          })
          issues.push('radiotap-unknown-present-masked')
        }
        return { headerLen, coverage, issues }
      }
      pos = align(pos, itStart, spec.align)
      if (pos + spec.size > offset + headerLen) {
        issues.push('radiotap-field-trunc')
        break
      }
      if (spec.action === 'mask') {
        maskBytes(collector, intents, packetIndex, pos, spec.size, spec.domain, 'radiotap')
        coverage.push({
          protocol: 'radiotap-gps',
          offset: pos,
          length: spec.size,
          status: 'redacted',
        })
      } else if (spec.action === 'vendor') {
        // Vendor namespace: align 2, then OUI(3)+sub(1)+len(2) then data
        pos = align(pos, itStart, 2)
        if (pos + 6 > offset + headerLen) break
        const vlen = readU16le(data, pos + 4)
        const total = 6 + vlen
        if (pos + total > offset + headerLen) {
          maskBytes(
            collector,
            intents,
            packetIndex,
            pos,
            offset + headerLen - pos,
            'radiotap-vendor',
            'radiotap',
          )
        } else {
          // Preserve OUI; mask data (may carry GPS / location)
          if (vlen > 0) {
            maskBytes(
              collector,
              intents,
              packetIndex,
              pos + 6,
              vlen,
              'radiotap-vendor',
              'radiotap',
            )
          }
          coverage.push({
            protocol: 'radiotap-vendor',
            offset: pos,
            length: total,
            status: 'redacted',
          })
        }
        pos += total
        continue
      }
      // preserve channel/rate/flags/TSFT/RSSI — no patch
      pos += spec.size
    }
  }

  coverage.push({ protocol: 'radiotap', offset, length: headerLen, status: 'covered' })
  return { headerLen, coverage, issues }
}

type FieldSpec = {
  readonly align: number
  readonly size: number
  readonly action: 'preserve' | 'mask' | 'vendor'
  readonly domain: string
}

/** Subset of radiotap present bits used in baseline walks. */
const RADIOTAP_FIELD: Record<number, FieldSpec> = {
  0: { align: 8, size: 8, action: 'preserve', domain: 'tsft' }, // TSFT
  1: { align: 1, size: 1, action: 'preserve', domain: 'flags' },
  2: { align: 1, size: 1, action: 'preserve', domain: 'rate' },
  3: { align: 2, size: 4, action: 'preserve', domain: 'channel' },
  4: { align: 2, size: 2, action: 'preserve', domain: 'fhss' },
  5: { align: 1, size: 1, action: 'preserve', domain: 'dbm-antsignal' },
  6: { align: 1, size: 1, action: 'preserve', domain: 'dbm-antnoise' },
  7: { align: 2, size: 2, action: 'preserve', domain: 'lock-quality' },
  8: { align: 2, size: 2, action: 'preserve', domain: 'tx-attenuation' },
  9: { align: 2, size: 2, action: 'preserve', domain: 'db-tx-attenuation' },
  10: { align: 1, size: 1, action: 'preserve', domain: 'dbm-tx-power' },
  11: { align: 1, size: 1, action: 'preserve', domain: 'antenna' },
  12: { align: 1, size: 1, action: 'preserve', domain: 'db-antsignal' },
  13: { align: 1, size: 1, action: 'preserve', domain: 'db-antnoise' },
  14: { align: 2, size: 2, action: 'preserve', domain: 'rx-flags' },
  15: { align: 2, size: 2, action: 'preserve', domain: 'tx-flags' },
  16: { align: 1, size: 1, action: 'preserve', domain: 'rts-retries' },
  17: { align: 1, size: 1, action: 'preserve', domain: 'data-retries' },
  18: { align: 4, size: 8, action: 'preserve', domain: 'xchannel' },
  19: { align: 1, size: 3, action: 'preserve', domain: 'mcs' },
  20: { align: 4, size: 8, action: 'preserve', domain: 'ampdu' },
  21: { align: 2, size: 12, action: 'preserve', domain: 'vht' },
  22: { align: 8, size: 12, action: 'preserve', domain: 'timestamp' },
  23: { align: 2, size: 12, action: 'preserve', domain: 'he' },
  24: { align: 2, size: 12, action: 'preserve', domain: 'he-mu' },
  29: { align: 2, size: 0, action: 'vendor', domain: 'vendor' }, // size dynamic
  30: { align: 2, size: 0, action: 'vendor', domain: 'vendor' },
}
