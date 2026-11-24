/**
 * T28 — ESP / AH (IP proto 50/51).
 * SPI → opaque-id; payload never encrypted-preserved without documented SA
 * (NULL encryption is not confidentiality).
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { LayerCoverage } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'

export const IPPROTO_ESP = 50
export const IPPROTO_AH = 51

export function sanitizeEsp(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number; issues: string[] } {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const length = data.length - offset
  if (length < 8) {
    coverage.push({ protocol: 'esp', offset, length, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset, issues: ['esp-trunc'] }
  }
  // SPI (4) → opaque-id consistent mask; sequence (4) preserve
  const spiHex = bytesToHex(data.subarray(offset, offset + 4))
  collector.addDeferred(
    offset,
    4,
    (ctx) => {
      const alias = ctx.mapping.map('opaque-id', spiHex)
      return createProtocolNeutralMaskFill({
        length: 4,
        packetIndex,
        offset,
        domain: `esp-spi:${alias}`,
      })
    },
    { fallbackKind: 'binary-mask', protocol: 'esp', category: 'opaque-id', packetIndex },
  )
  intents?.recordMaskRange(packetIndex, offset, 4, 'esp-spi', 'esp')
  // Remainder: no SA proof → mask (NULL encryption would otherwise leak plaintext)
  if (length > 8) {
    const fill = createProtocolNeutralMaskFill({
      length: length - 8,
      packetIndex,
      offset: offset + 8,
      domain: 'esp-payload-no-sa',
    })
    collector.maskRange(offset + 8, fill)
    intents?.recordMaskRange(packetIndex, offset + 8, length - 8, 'esp-payload-no-sa', 'esp')
  }
  coverage.push({ protocol: 'esp', offset, length, status: 'redacted' })
  issues.push('esp-sa-unproven')
  return { coverage, lastCoveredOffset: data.length, issues }
}

export function sanitizeAh(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; lastCoveredOffset: number; issues: string[] } {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const length = data.length - offset
  if (length < 12) {
    coverage.push({ protocol: 'ah', offset, length, status: 'malformed' })
    return { coverage, lastCoveredOffset: offset, issues: ['ah-trunc'] }
  }
  // Next header + payload len + reserved + SPI + seq + ICV…
  const payloadLen = data[offset + 1]! // in 32-bit words, minus 2
  const headerBytes = (payloadLen + 2) * 4
  const icvOff = offset + 12
  const icvLen = Math.max(0, Math.min(headerBytes, length) - 12)
  if (icvLen > 0) {
    const fill = createProtocolNeutralMaskFill({
      length: icvLen,
      packetIndex,
      offset: icvOff,
      domain: 'ah-icv',
    })
    collector.maskRange(icvOff, fill)
    intents?.recordMaskRange(packetIndex, icvOff, icvLen, 'ah-icv', 'ah')
  }
  coverage.push({ protocol: 'ah', offset, length: Math.min(headerBytes, length), status: 'redacted' })
  issues.push('crypto-integrity-modified:ah')
  // Inner protocol continues after AH header — caller may decode further; we stop at AH.
  return { coverage, lastCoveredOffset: offset + Math.min(headerBytes, length), issues }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    s += bytes[i]!.toString(16).padStart(2, '0')
  }
  return s
}
