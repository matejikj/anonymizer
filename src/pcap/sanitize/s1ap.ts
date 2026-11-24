/**
 * T57 — S1AP (TS 36.413) sanitizer over SCTP PPID 18 via T56 APER.
 * UE S1AP IDs scoped map; NAS-PDU → T59; GTP-TEID/TLA → T26; SecurityKey/TAI/unknown mask.
 */

import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { PatchCollector } from './PatchCollector.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { createProtocolNeutralMaskFill } from './maskFill.ts'
import { computeFixedLengthAsciiBytes } from './textPatch.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import {
  decodeAper,
  encodeAper,
  rewriteConstrainedIntegerLeaf,
  S1AP_PDU_TYPE,
  S1AP_IE,
  ieValueSchema,
  MME_UE_S1AP_ID_TYPE,
  ENB_UE_S1AP_ID_TYPE,
  type DecodedLeaf,
  type AperTypeDesc,
} from '../protocols/asn1/aper/index.ts'
import { sanitizeNas, looksLikeNas } from './nas.ts'
import { patchTeid } from './gtp.ts'

/** IANA SCTP Payload Protocol Identifier for S1AP. */
export const PPID_S1AP = 18

export function looksLikeS1ap(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 2) return false
  // Extensible CHOICE: extension bit 0 + index in 0..2 for three root alts
  const dec = decodeAper(data, offset, length, S1AP_PDU_TYPE)
  return dec.ok || dec.leaves.some((l) => l.path.includes('procedureCode'))
}

export function sanitizeS1ap(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  /** V17 — SCTP association / node generation scope for UE IDs. */
  identityScope?: string,
): AppLayerResult | null {
  if (length < 2) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  const dec = decodeAper(buffer, offset, length, S1AP_PDU_TYPE)
  if (!dec.ok && dec.leaves.length === 0) {
    maskSpan(collector, intents, packetIndex, offset, length, 's1ap-aper-fail')
    coverage.push({ protocol: 's1ap', offset, length, status: 'malformed' })
    issues.push('s1ap-aper-fail')
    return { coverage, issues }
  }

  coverage.push({ protocol: 's1ap', offset, length: Math.max(1, (dec.bitLength + 7) >> 3), status: 'covered' })

  const procLeaf = dec.leaves.find((l) => l.path.endsWith('procedureCode'))
  if (procLeaf && typeof procLeaf.value === 'number') {
    coverage.push({
      protocol: 's1ap-procedure',
      offset: offset + (procLeaf.span.bitOffset >> 3),
      length: 1,
      status: 'covered',
    })
  }

  // Pair ProtocolIE id + value open-type spans from container walk
  const ies = collectIePairs(dec.leaves)
  for (const ie of ies) {
    sanitizeIe(
      buffer,
      offset,
      ie.id,
      ie.valueSpan,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
      identityScope,
    )
  }

  // Residual: if decode failed mid-way, mask unread tail
  const consumed = (dec.bitLength + 7) >> 3
  if (consumed < length && !dec.ok) {
    maskSpan(collector, intents, packetIndex, offset + consumed, length - consumed, 's1ap-tail')
    coverage.push({
      protocol: 's1ap-tail',
      offset: offset + consumed,
      length: length - consumed,
      status: 'redacted',
    })
    issues.push('s1ap-partial-decode')
  }

  return { coverage, issues }
}

interface IePair {
  readonly id: number
  readonly valueSpan: { bitOffset: number; bitLength: number }
}

function collectIePairs(leaves: readonly DecodedLeaf[]): IePair[] {
  const out: IePair[] = []
  // Paths look like: initiatingMessage.value.open[i].id / .value
  const byIndex = new Map<string, { id?: number; valueSpan?: IePair['valueSpan'] }>()
  for (const leaf of leaves) {
    const m = /^(.*\[[0-9]+\])\.(id|value)$/.exec(leaf.path)
    if (!m) continue
    const key = m[1]!
    const field = m[2]!
    let slot = byIndex.get(key)
    if (!slot) {
      slot = {}
      byIndex.set(key, slot)
    }
    if (field === 'id' && typeof leaf.value === 'number') {
      slot.id = leaf.value
    } else if (field === 'value') {
      slot.valueSpan = leaf.span
    }
  }
  for (const slot of byIndex.values()) {
    if (slot.id !== undefined && slot.valueSpan && slot.valueSpan.bitLength > 0) {
      out.push({ id: slot.id, valueSpan: slot.valueSpan })
    }
  }
  return out
}

function sanitizeIe(
  buffer: Uint8Array,
  pduOffset: number,
  ieId: number,
  valueSpan: { bitOffset: number; bitLength: number },
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  identityScope?: string,
): void {
  // Open-type content is byte-aligned relative to PDU start (absolute bit offset in buffer)
  if ((valueSpan.bitOffset & 7) !== 0 || (valueSpan.bitLength & 7) !== 0) {
    maskBitSpan(collector, intents, packetIndex, buffer, valueSpan, 's1ap-ie-unaligned')
    coverage.push({
      protocol: 's1ap-ie',
      offset: valueSpan.bitOffset >> 3,
      length: (valueSpan.bitLength + 7) >> 3,
      status: 'redacted',
    })
    issues.push(`s1ap-ie-unaligned:${ieId}`)
    return
  }
  const abs = valueSpan.bitOffset >> 3
  const len = valueSpan.bitLength >> 3
  const schema = ieValueSchema(ieId)

  switch (ieId) {
    case S1AP_IE.MME_UE_S1AP_ID:
      mapUeS1apId(buffer, abs, len, 'mme', MME_UE_S1AP_ID_TYPE, collector, mapping, intents, packetIndex, coverage, identityScope)
      return
    case S1AP_IE.ENB_UE_S1AP_ID:
      mapUeS1apId(buffer, abs, len, 'enb', ENB_UE_S1AP_ID_TYPE, collector, mapping, intents, packetIndex, coverage, identityScope)
      return
    case S1AP_IE.NAS_PDU:
      sanitizeNasPdu(buffer, abs, len, collector, mapping, intents, packetIndex, coverage, issues)
      return
    case S1AP_IE.CAUSE:
      // Preserve — re-decode to confirm
      if (schema) {
        const d = decodeAper(buffer, abs, len, schema)
        coverage.push({
          protocol: 's1ap-cause',
          offset: abs,
          length: len,
          status: d.ok ? 'covered' : 'redacted',
        })
        if (!d.ok) {
          maskSpan(collector, intents, packetIndex, abs, len, 's1ap-cause-bad')
          issues.push('s1ap-cause-bad')
        }
      }
      return
    case S1AP_IE.SECURITY_KEY:
      maskSpan(collector, intents, packetIndex, abs, len, 's1ap-security-key')
      coverage.push({ protocol: 's1ap-security-key', offset: abs, length: len, status: 'redacted' })
      return
    case S1AP_IE.TAI:
    case S1AP_IE.EUTRAN_CGI:
    case S1AP_IE.GUMMEI:
    case S1AP_IE.GLOBAL_MME_ID:
    case S1AP_IE.S_TMSI:
      maskSpan(collector, intents, packetIndex, abs, len, 's1ap-location')
      coverage.push({ protocol: 's1ap-location', offset: abs, length: len, status: 'redacted' })
      return
    case S1AP_IE.SOURCE_TO_TARGET_TRANSPARENT_CONTAINER:
    case S1AP_IE.TARGET_TO_SOURCE_TRANSPARENT_CONTAINER:
      maskSpan(collector, intents, packetIndex, abs, len, 's1ap-transparent-container')
      coverage.push({
        protocol: 's1ap-transparent-container',
        offset: abs,
        length: len,
        status: 'redacted',
      })
      issues.push('s1ap-rrc-transparent-mask')
      return
    case S1AP_IE.UE_AGGREGATE_MAXIMUM_BITRATE:
      if (schema) {
        const d = decodeAper(buffer, abs, len, schema)
        coverage.push({
          protocol: 's1ap-qos-ambr',
          offset: abs,
          length: len,
          status: d.ok ? 'covered' : 'redacted',
        })
        if (!d.ok) {
          maskSpan(collector, intents, packetIndex, abs, len, 's1ap-ambr-bad')
          issues.push('s1ap-ambr-bad')
        }
      }
      return
    case S1AP_IE.ENB_NAME:
    case S1AP_IE.MME_NAME:
      mapNodeName(buffer, abs, len, collector, mapping, intents, packetIndex, coverage)
      return
    case S1AP_IE.GLOBAL_ENB_ID:
      mapGlobalEnbId(buffer, abs, len, schema!, collector, mapping, intents, packetIndex, coverage, issues)
      return
    case S1AP_IE.E_RAB_TO_BE_SETUP_ITEM_BEARER:
    case S1AP_IE.E_RAB_TO_BE_SETUP_ITEM_CTX:
      mapErabItem(buffer, abs, len, schema!, collector, mapping, intents, packetIndex, coverage, issues)
      return
    default:
      maskSpan(collector, intents, packetIndex, abs, len, `s1ap-ie-${ieId}`)
      coverage.push({ protocol: 's1ap-ie', offset: abs, length: len, status: 'redacted' })
      void pduOffset
  }
}

function mapUeS1apId(
  buffer: Uint8Array,
  abs: number,
  len: number,
  role: 'mme' | 'enb',
  type: AperTypeDesc,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  identityScope?: string,
): void {
  const dec = decodeAper(buffer, abs, len, type)
  const leaf = dec.leaves[0]
  if (!dec.ok || !leaf || typeof leaf.value !== 'number') {
    maskSpan(collector, intents, packetIndex, abs, len, `s1ap-${role}-ue-id-bad`)
    coverage.push({ protocol: `s1ap-${role}-ue-id`, offset: abs, length: len, status: 'redacted' })
    return
  }
  const original = leaf.value
  const scopePrefix = identityScope && identityScope.length > 0 ? `${identityScope}:` : ''
  const canon =
    canonicalizeIdentity('opaque-id', `s1ap-${role}-ue:${scopePrefix}${original}`)
    ?? `s1ap-${role}-ue:${scopePrefix}${original}`
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len)
  const lower = type.kind === 'integer' ? type.lower : 0
  const upper = type.kind === 'integer' ? type.upper : 0
  // Retain only the IE window (not the whole packet) for deferred APER rewrite (V11).
  const ieBytes = buffer.subarray(abs, abs + len).slice()
  const localSpan = {
    bitOffset: leaf.span.bitOffset - abs * 8,
    bitLength: leaf.span.bitLength,
  }
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const alias = live.map('opaque-id', canon)
      let h = 2166136261 >>> 0
      for (let i = 0; i < alias.length; i++) {
        h ^= alias.charCodeAt(i)
        h = Math.imul(h, 16777619)
      }
      const domain = upper - lower + 1
      let mapped = lower + (h % domain)
      if (mapped === original) mapped = lower + ((h + 1) % domain)
      if (mapped === 0 && original !== 0) mapped = 1
      const copy = ieBytes.slice()
      const direct = rewriteConstrainedIntegerLeaf(copy, localSpan, lower, upper, mapped)
      if (direct.ok) return copy
      return createProtocolNeutralMaskFill({
        length: len, packetIndex, offset: abs, domain: `s1ap-${role}-ue`,
      })
    } catch {
      return createProtocolNeutralMaskFill({
        length: len, packetIndex, offset: abs, domain: `s1ap-${role}-ue`,
      })
    }
  }, { fallbackKind: 'binary-mask', protocol: 's1ap', category: 'opaque-id', packetIndex })
  coverage.push({ protocol: `s1ap-${role}-ue-id`, offset: abs, length: len, status: 'covered' })
  void mapping
}

function sanitizeNasPdu(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  // Open-type may wrap OCTET STRING with length determinant — decode first
  const schema = ieValueSchema(S1AP_IE.NAS_PDU)
  if (!schema) {
    maskSpan(collector, intents, packetIndex, abs, len, 's1ap-nas')
    return
  }
  const dec = decodeAper(buffer, abs, len, schema)
  const leaf = dec.leaves.find((l) => l.value instanceof Uint8Array)
  if (!dec.ok || !leaf || !(leaf.value instanceof Uint8Array)) {
    maskSpan(collector, intents, packetIndex, abs, len, 's1ap-nas-bad')
    coverage.push({ protocol: 's1ap-nas', offset: abs, length: len, status: 'redacted' })
    issues.push('s1ap-nas-bad')
    return
  }
  const nasOff = leaf.span.bitOffset >> 3
  const nasLen = leaf.span.bitLength >> 3
  if (looksLikeNas(buffer, nasOff, nasLen)) {
    const nas = sanitizeNas(buffer, nasOff, nasLen, collector, mapping, intents, packetIndex)
    if (nas) {
      coverage.push(...nas.coverage)
      if (nas.issues) issues.push(...nas.issues)
      coverage.push({ protocol: 's1ap-nas', offset: abs, length: len, status: 'covered' })
      return
    }
  }
  maskSpan(collector, intents, packetIndex, nasOff, nasLen, 's1ap-nas-opaque')
  coverage.push({ protocol: 's1ap-nas', offset: abs, length: len, status: 'redacted' })
  issues.push('s1ap-nas-unrecognized')
}

function mapNodeName(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  const schema = ieValueSchema(S1AP_IE.ENB_NAME)!
  const dec = decodeAper(buffer, abs, len, schema)
  const leaf = dec.leaves.find((l) => l.value instanceof Uint8Array)
  if (!dec.ok || !leaf || !(leaf.value instanceof Uint8Array)) {
    maskSpan(collector, intents, packetIndex, abs, len, 's1ap-name-bad')
    coverage.push({ protocol: 's1ap-node-name', offset: abs, length: len, status: 'redacted' })
    return
  }
  const nameOff = leaf.span.bitOffset >> 3
  const nameLen = leaf.span.bitLength >> 3
  let text = ''
  for (let i = 0; i < nameLen; i++) {
    const c = buffer[nameOff + i]!
    if (c < 0x20 || c > 0x7e) {
      maskSpan(collector, intents, packetIndex, nameOff, nameLen, 's1ap-name-bin')
      coverage.push({ protocol: 's1ap-node-name', offset: abs, length: len, status: 'redacted' })
      return
    }
    text += String.fromCharCode(c)
  }
  const canon = canonicalizeIdentity('hostname', text.toLowerCase())
  if (!canon) {
    maskSpan(collector, intents, packetIndex, nameOff, nameLen, 's1ap-name-bad')
    coverage.push({ protocol: 's1ap-node-name', offset: abs, length: len, status: 'redacted' })
    return
  }
  intents?.recordEntityReplacement(packetIndex, nameOff, 'hostname', canon, nameLen)
  collector.addDeferred(nameOff, nameLen, ({ mapping: live }) => {
    try {
      const mapped = live.map('hostname', canon)
      return computeFixedLengthAsciiBytes(nameOff, nameLen, mapped)
    } catch {
      return createProtocolNeutralMaskFill({
        length: nameLen, packetIndex, offset: nameOff, domain: 's1ap-name',
      })
    }
  }, { fallbackKind: 'text-x', protocol: 's1ap', category: 'hostname', packetIndex })
  coverage.push({ protocol: 's1ap-node-name', offset: abs, length: len, status: 'covered' })
  void mapping
}

function mapGlobalEnbId(
  buffer: Uint8Array,
  abs: number,
  len: number,
  schema: AperTypeDesc,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const dec = decodeAper(buffer, abs, len, schema)
  if (!dec.ok) {
    maskSpan(collector, intents, packetIndex, abs, len, 's1ap-global-enb-bad')
    coverage.push({ protocol: 's1ap-global-enb-id', offset: abs, length: len, status: 'redacted' })
    issues.push('s1ap-global-enb-bad')
    return
  }
  const enb = dec.leaves.find((l) => l.path.includes('macroENB-ID') && typeof l.value === 'number')
  if (enb && typeof enb.value === 'number') {
    const canon = canonicalizeIdentity('opaque-id', `s1ap-enb:${enb.value}`) ?? `s1ap-enb:${enb.value}`
    const byteOff = enb.span.bitOffset >> 3
    const byteLen = Math.max(1, (enb.span.bitLength + 7) >> 3)
    intents?.recordEntityReplacement(packetIndex, byteOff, 'opaque-id', canon, byteLen)
    collector.addDeferred(byteOff, byteLen, ({ mapping: live }) => {
      const alias = live.map('opaque-id', canon)
      return createProtocolNeutralMaskFill({
        length: byteLen, packetIndex, offset: byteOff, domain: `s1ap-enb:${alias}`,
      })
    })
  }
  coverage.push({ protocol: 's1ap-global-enb-id', offset: abs, length: len, status: 'covered' })
  void mapping
}

function mapErabItem(
  buffer: Uint8Array,
  abs: number,
  len: number,
  schema: AperTypeDesc,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const dec = decodeAper(buffer, abs, len, schema)
  if (!dec.ok) {
    maskSpan(collector, intents, packetIndex, abs, len, 's1ap-erab-bad')
    coverage.push({ protocol: 's1ap-erab', offset: abs, length: len, status: 'redacted' })
    issues.push('s1ap-erab-bad')
    return
  }
  // transportLayerAddress: 32-bit value in leaf — map as IPv4
  let receiveEndpoint: string | undefined
  const tla = dec.leaves.find((l) => l.path.endsWith('transportLayerAddress') && typeof l.value === 'number')
  if (tla && typeof tla.value === 'number' && tla.span.bitLength === 32) {
    const ipOff = tla.span.bitOffset >> 3
    receiveEndpoint =
      `${buffer[ipOff]}.${buffer[ipOff + 1]}.${buffer[ipOff + 2]}.${buffer[ipOff + 3]}`
    if (receiveEndpoint === '0.0.0.0') receiveEndpoint = undefined
    patchIpv4FromBits(buffer, ipOff, tla.value >>> 0, collector, mapping, intents, packetIndex)
  }
  const teid = dec.leaves.find((l) => l.path.endsWith('gtpTeid') && l.value instanceof Uint8Array)
  if (teid && teid.value instanceof Uint8Array && teid.value.length === 4) {
    const teidOff = teid.span.bitOffset >> 3
    patchTeid(
      buffer,
      teidOff,
      collector,
      mapping,
      intents,
      packetIndex,
      receiveEndpoint ? { receiveEndpoint, plane: 'u' } : undefined,
    )
  }
  coverage.push({ protocol: 's1ap-erab', offset: abs, length: len, status: 'covered' })
}

function patchIpv4FromBits(
  buffer: Uint8Array,
  offset: number,
  _packed: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const ip = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`
  if (ip === '0.0.0.0') return
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', ip, 4)
  collector.addDeferred(offset, 4, ({ mapping: live }) => {
    const mapped = live.map('ipv4', ip)
    return new Uint8Array(mapped.split('.').map(Number))
  })
}

function maskSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  intents?.recordMaskRange(packetIndex, offset, length, domain, 's1ap')
  collector.addDeferred(offset, length, () => createProtocolNeutralMaskFill({
    length, packetIndex, offset, domain,
  }))
}

function maskBitSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  buffer: Uint8Array,
  span: { bitOffset: number; bitLength: number },
  domain: string,
): void {
  const off = span.bitOffset >> 3
  const len = Math.min(buffer.length - off, (span.bitLength + 7) >> 3)
  maskSpan(collector, intents, packetIndex, off, len, domain)
}

/** Test helper: build a synthetic S1AP PDU via T56 encode. */
export function encodeS1apPdu(args: {
  readonly outcome: 'initiatingMessage' | 'successfulOutcome' | 'unsuccessfulOutcome'
  readonly procedureCode: number
  readonly criticality?: 'reject' | 'ignore' | 'notify'
  readonly ies: readonly { id: number; criticality?: 'reject' | 'ignore' | 'notify'; value: Uint8Array }[]
}): Uint8Array | null {
  const ies = args.ies.map((ie) => ({
    id: ie.id,
    criticality: ie.criticality ?? 'reject',
    value: ie.value,
  }))
  return encodeAper(
    S1AP_PDU_TYPE,
    {
      alt: args.outcome,
      value: {
        procedureCode: args.procedureCode,
        criticality: args.criticality ?? 'ignore',
        value: ies,
      },
    },
    4096,
  )
}

export function encodeIeValue(type: AperTypeDesc, value: unknown): Uint8Array | null {
  return encodeAper(type, value, 2048)
}
