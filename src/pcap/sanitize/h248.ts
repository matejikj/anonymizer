/**
 * T24 — H.248 / MEGACO text profile (UDP/TCP 2944/2945).
 * Binary ASN.1 BER → identify+mask. Nested Local/Remote SDP → shared SDP path + media flows.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import {
  extractTextProtoValues,
  applyPayloadMapHits,
  hitsFromExtractors,
  maskPayloadSpan,
} from '../protocols/application/textproto'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { sanitizeEmbeddedSdpSpan } from './embeddedSdp'

const H248_PORTS = new Set([2944, 2945])

export function isH248PortHint(src: number, dst: number): boolean {
  return H248_PORTS.has(src) || H248_PORTS.has(dst)
}

export function looksLikeH248Text(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const head = latin1(data, offset, Math.min(length, 96))
  return /MEGACO\/1/i.test(head) || /^!?\/?MEGACO\//i.test(head.trimStart())
}

export function looksLikeH248Binary(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 2) return false
  const tag = data[offset]!
  return tag === 0x30 || (tag & 0xc0) === 0x40 || (tag & 0xc0) === 0x80
}

export function sanitizeH248(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  mediaFlowIndex?: MediaFlowIndex,
): AppLayerResult | null {
  if (looksLikeH248Text(buffer, offset, length)) {
    return sanitizeH248Text(
      buffer, offset, length, collector, mapping, intents, packetIndex, mediaFlowIndex,
    )
  }
  if (looksLikeH248Binary(buffer, offset, length)) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'h248-ber')
    return {
      coverage: [{ protocol: 'h248-ber', offset, length, status: 'redacted' }],
      issues: ['h248-ber-identify-mask'],
    }
  }
  return null
}

function sanitizeH248Text(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  mediaFlowIndex: MediaFlowIndex | undefined,
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const text = latin1(buffer, offset, length)

  // MID / first line only — nested Local/Remote SDP owns its own address spans (no overlap).
  const firstNl = text.indexOf('\n')
  const headLen = firstNl < 0 ? text.length : firstNl
  const hits = hitsFromExtractors(extractTextProtoValues(text.slice(0, headLen), offset))
  applyPayloadMapHits(hits, collector, mapping, intents, packetIndex, 'h248')

  const dsRe = /\bds\s*=\s*"([^"]*)"/gi
  let m: RegExpExecArray | null
  while ((m = dsRe.exec(text)) !== null) {
    const digits = m[1]!
    const abs = offset + m.index + m[0]!.indexOf(digits)
    if (digits.length > 0) {
      maskPayloadSpan(collector, abs, digits.length, intents, packetIndex, 'h248-ds')
      coverage.push({ protocol: 'h248-digit', offset: abs, length: digits.length, status: 'redacted' })
    }
  }

  let searchFrom = 0
  while (searchFrom < text.length) {
    const v0 = text.indexOf('v=0', searchFrom)
    if (v0 < 0) break
    let end = text.length
    const nextCmd = text.slice(v0).search(/\r?\n\s*(?:Local|Remote|Media|Events|Signals|Audit|Topology|Error)\b/i)
    if (nextCmd > 0) end = v0 + nextCmd
    while (end > v0 && /[\s}]/.test(text[end - 1]!)) end--
    const sdpLen = end - v0
    if (sdpLen >= 8) {
      sanitizeEmbeddedSdpSpan(
        buffer, offset + v0, sdpLen, collector, mapping, intents, packetIndex,
        coverage, issues, mediaFlowIndex, null, 'h248',
      )
    }
    searchFrom = v0 + 3
  }

  coverage.unshift({ protocol: 'h248', offset, length, status: 'covered' })
  return { coverage, issues }
}

function latin1(buf: Uint8Array, off: number, len: number): string {
  let s = ''
  for (let i = 0; i < len; i++) s += String.fromCharCode(buf[off + i]!)
  return s
}
