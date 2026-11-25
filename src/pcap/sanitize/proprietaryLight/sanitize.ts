/**
 * T74 — diagnostic light anonymization for unknown / proprietary payloads.
 *
 * High-privacy never calls this (unsupported → truncate). Diagnostic keeps
 * structure: map known identities + text + sender-bound ids; mask location /
 * media-entropy; leave constants/counters/unclassified (preserve-inferred).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult, LayerCoverage } from '../types.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { sanitizeTextPayload } from '../../protocols/application/textproto/index.ts'
import { PCAP_KERNEL_BUDGETS } from '../../../domain/capabilityContract.ts'
import { ProprietaryLightSession } from './session.ts'

function isPrintableAsciiByte(b: number): boolean {
  return b === 0x09 || b === 0x0a || b === 0x0d || (b >= 0x20 && b <= 0x7e)
}

function shannonEntropy(buf: Uint8Array, offset: number, length: number): number {
  if (length <= 0) return 0
  const counts = new Uint32Array(256)
  for (let i = 0; i < length; i++) counts[buf[offset + i]!]!++
  let h = 0
  for (let i = 0; i < 256; i++) {
    const c = counts[i]!
    if (c === 0) continue
    const p = c / length
    h -= p * Math.log2(p)
  }
  return h
}

function looksLikeLatLonPair(buf: Uint8Array, offset: number): boolean {
  if (offset + 8 > buf.length) return false
  const view = new DataView(buf.buffer, buf.byteOffset + offset, 8)
  for (const le of [false, true]) {
    const a = view.getFloat32(0, le)
    const b = view.getFloat32(4, le)
    if (
      Number.isFinite(a)
      && Number.isFinite(b)
      && a >= -90
      && a <= 90
      && b >= -180
      && b <= 180
      && Math.abs(a) > 0.01
      && Math.abs(b) > 0.01
    ) {
      return true
    }
  }
  return false
}

function bytesToHex(buf: Uint8Array, offset: number, length: number): string {
  let out = ''
  for (let i = 0; i < length; i++) out += buf[offset + i]!.toString(16).padStart(2, '0')
  return out
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16) & 0xff
  }
  return out
}

function looksLikeIpv4(buf: Uint8Array, abs: number): boolean {
  const a = buf[abs]!
  const b = buf[abs + 1]!
  const d = buf[abs + 3]!
  if (a === 0 || a >= 224) return false
  if (d === 0 || d === 255) return false
  // Prefer private / common lab ranges to cut false positives.
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  reason: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({
    length,
    packetIndex,
    offset,
    domain: reason,
  })
  try {
    collector.maskRange(offset, fill)
  } catch {
    try {
      collector.add(offset, fill)
    } catch {
      /* overlap */
    }
  }
  intents?.recordMaskRange(packetIndex, offset, length, reason, 'proprietary-light')
}

function mapIpv4(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const a = buffer[abs]!
  const b = buffer[abs + 1]!
  const c = buffer[abs + 2]!
  const d = buffer[abs + 3]!
  const canon = `${a}.${b}.${c}.${d}`
  const constraint = { kind: 'ipv4-wire' as const }
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv4', canon, 4, constraint, canon)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    try {
      const mapped = live.aliasFor('ipv4', canon, constraint, canon)
      const parts = mapped.split('.').map((x) => Number(x) & 0xff)
      if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) {
        return createProtocolNeutralMaskFill({ length: 4, packetIndex, offset: abs, domain: 'ipv4-fallback' })
      }
      return new Uint8Array(parts)
    } catch {
      return createProtocolNeutralMaskFill({ length: 4, packetIndex, offset: abs, domain: 'ipv4-fallback' })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'proprietary-light', category: 'ipv4', packetIndex })
}

function mapMac(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const canon = bytesToHex(buffer, abs, 6).match(/.{2}/g)!.join(':')
  const constraint = { kind: 'mac-wire' as const }
  intents?.recordEntityReplacement(packetIndex, abs, 'mac', canon, 6, constraint, canon)
  collector.addDeferred(abs, 6, ({ mapping: live }) => {
    try {
      const mapped = live.aliasFor('mac', canon, constraint, canon)
      const parts = mapped.split(':').map((x) => Number.parseInt(x, 16) & 0xff)
      if (parts.length !== 6 || parts.some((n) => !Number.isFinite(n))) {
        return createProtocolNeutralMaskFill({ length: 6, packetIndex, offset: abs, domain: 'mac-fallback' })
      }
      return new Uint8Array(parts)
    } catch {
      return createProtocolNeutralMaskFill({ length: 6, packetIndex, offset: abs, domain: 'mac-fallback' })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'proprietary-light', category: 'mac', packetIndex })
}

function mapOpaqueBin(
  buffer: Uint8Array,
  abs: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const hex = bytesToHex(buffer, abs, length)
  const constraint = { kind: 'text-ascii' as const, byteLength: hex.length }
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-bin-id', hex, length, constraint, hex)
  collector.addDeferred(abs, length, ({ mapping: live }) => {
    try {
      const mappedHex = live.map('opaque-bin-id', hex)
      if (mappedHex.length !== hex.length) {
        return createProtocolNeutralMaskFill({
          length,
          packetIndex,
          offset: abs,
          domain: 'opaque-bin-fallback',
        })
      }
      return hexToBytes(mappedHex)
    } catch {
      return createProtocolNeutralMaskFill({
        length,
        packetIndex,
        offset: abs,
        domain: 'opaque-bin-fallback',
      })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'proprietary-light', category: 'opaque-bin-id', packetIndex })
}

function scanAsciiRuns(
  buffer: Uint8Array,
  offset: number,
  length: number,
): Array<{ start: number; length: number }> {
  const runs: Array<{ start: number; length: number }> = []
  let i = 0
  while (i < length) {
    if (!isPrintableAsciiByte(buffer[offset + i]!)) {
      i++
      continue
    }
    const start = i
    i++
    while (i < length && isPrintableAsciiByte(buffer[offset + i]!)) i++
    if (i - start >= 4) runs.push({ start: offset + start, length: i - start })
  }
  return runs
}

/**
 * Apply T74 light anonymization. Caller must only invoke in diagnostic mode.
 */
export function sanitizeProprietaryLight(input: {
  readonly buffer: Uint8Array
  readonly offset: number
  readonly length: number
  readonly collector: PatchCollector
  readonly mapping: MappingLike
  readonly intents?: IntentCollector
  readonly packetIndex: number
  readonly session: ProprietaryLightSession
  readonly flowKey: string
  readonly senderKey: string
  readonly protocolId?: string
}): AppLayerResult {
  const {
    buffer,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
    session,
    flowKey,
    senderKey,
  } = input
  const protocolId = input.protocolId ?? 'proprietary-light'

  if (length <= 0) {
    return { coverage: [{ protocol: protocolId, offset, length: 0, status: 'covered' }] }
  }

  const obs = session.observe({ flowKey, senderKey, buffer, offset, length })
  if (obs.budgetExceeded || !obs.ready) {
    maskRange(collector, intents, packetIndex, offset, length, `${protocolId}-insufficient-stats`)
    return {
      coverage: [{ protocol: protocolId, offset, length, status: 'redacted' }],
    }
  }

  const claimed = new Uint8Array(length)
  const mark = (rel: number, len: number) => {
    for (let i = rel; i < rel + len && i < length; i++) claimed[i] = 1
  }
  const free = (rel: number, len: number) => {
    for (let i = rel; i < rel + len && i < length; i++) if (claimed[i]) return false
    return true
  }

  const scanLen = Math.min(length, PCAP_KERNEL_BUDGETS.proprietaryLightMaxPayloadBytes)

  // Location pairs (always mask).
  for (let rel = 0; rel + 8 <= scanLen; rel += 4) {
    if (!free(rel, 8)) continue
    if (looksLikeLatLonPair(buffer, offset + rel)) {
      maskRange(collector, intents, packetIndex, offset + rel, 8, `${protocolId}-location`)
      mark(rel, 8)
    }
  }

  // High-entropy media-like blocks ≥ 16 B.
  for (let rel = 0; rel + 16 <= scanLen; ) {
    const sliceLen = Math.min(64, scanLen - rel)
    if (sliceLen >= 16 && free(rel, sliceLen)) {
      const h = shannonEntropy(buffer, offset + rel, sliceLen)
      if (h >= 7.2) {
        maskRange(collector, intents, packetIndex, offset + rel, sliceLen, `${protocolId}-media-entropy`)
        mark(rel, sliceLen)
        rel += sliceLen
        continue
      }
    }
    rel += 16
  }

  // Sender-bound ids from cluster stats (before speculative IP/MAC).
  const classified = session.classifyOffsets(flowKey, obs.clusterKey)
  for (const field of classified) {
    if (field.rel + field.width > scanLen) continue
    if (!free(field.rel, field.width)) continue
    if (field.fieldClass === 'sender-bound-id') {
      mapOpaqueBin(buffer, offset + field.rel, field.width, collector, intents, packetIndex)
      mark(field.rel, field.width)
    }
  }

  // Conservative IPv4 BE candidates.
  for (let rel = 0; rel + 4 <= scanLen; rel++) {
    if (!free(rel, 4)) continue
    if (!looksLikeIpv4(buffer, offset + rel)) continue
    mapIpv4(buffer, offset + rel, collector, intents, packetIndex)
    mark(rel, 4)
  }

  // Unicast MAC candidates (OUI not 00:00:00).
  for (let rel = 0; rel + 6 <= scanLen; rel++) {
    if (!free(rel, 6)) continue
    const first = buffer[offset + rel]!
    if ((first & 0x01) !== 0) continue
    if (
      buffer[offset + rel]! === 0
      && buffer[offset + rel + 1]! === 0
      && buffer[offset + rel + 2]! === 0
    ) {
      continue
    }
    mapMac(buffer, offset + rel, collector, intents, packetIndex)
    mark(rel, 6)
  }

  // ASCII text runs → T69.
  for (const run of scanAsciiRuns(buffer, offset, scanLen)) {
    const rel = run.start - offset
    if (!free(rel, run.length)) continue
    sanitizeTextPayload({
      buffer,
      absoluteOffset: run.start,
      byteLength: run.length,
      collector,
      mapping,
      intents,
      packetIndex,
      highPrivacy: false,
      protocolId: `${protocolId}-text`,
    })
    mark(rel, run.length)
  }

  const coverage: LayerCoverage[] = [
    {
      protocol: protocolId,
      offset,
      length,
      status: 'preserved-for-diagnostics',
    },
  ]
  return { coverage }
}
