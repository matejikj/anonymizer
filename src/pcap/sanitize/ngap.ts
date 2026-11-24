/**
 * T58 — NGAP (TS 38.413) sanitizer over SCTP PPID 60 via T56 APER.
 * AMF/RAN UE NGAP IDs scoped map; NAS-PDU → T59; NG-U TEID/TLA → T26;
 * typed N2 transfer adapter for T61 (schemaTypeId, not whole-PDU guess).
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
  NGAP_PDU_TYPE,
  NGAP_IE,
  ngapIeValueSchema,
  AMF_UE_NGAP_ID_TYPE,
  RAN_UE_NGAP_ID_TYPE,
  n2TransferSchema,
  type N2TransferSchemaId,
  type DecodedLeaf,
  type AperTypeDesc,
} from '../protocols/asn1/aper/index.ts'
import { sanitizeNas, looksLikeNas } from './nas.ts'
import { patchTeid } from './gtp.ts'

/** IANA SCTP Payload Protocol Identifier for NGAP. */
export const PPID_NGAP = 60

export type { N2TransferSchemaId }

export function looksLikeNgap(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 2) return false
  const dec = decodeAper(data, offset, length, NGAP_PDU_TYPE)
  return dec.ok || dec.leaves.some((l) => l.path.includes('procedureCode'))
}

export function sanitizeNgap(
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

  const dec = decodeAper(buffer, offset, length, NGAP_PDU_TYPE)
  if (!dec.ok && dec.leaves.length === 0) {
    maskSpan(collector, intents, packetIndex, offset, length, 'ngap-aper-fail')
    coverage.push({ protocol: 'ngap', offset, length, status: 'malformed' })
    issues.push('ngap-aper-fail')
    return { coverage, issues }
  }

  coverage.push({
    protocol: 'ngap',
    offset,
    length: Math.max(1, (dec.bitLength + 7) >> 3),
    status: 'covered',
  })

  for (const ie of collectIePairs(dec.leaves)) {
    sanitizeIe(
      buffer,
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

  const consumed = (dec.bitLength + 7) >> 3
  if (consumed < length && !dec.ok) {
    maskSpan(collector, intents, packetIndex, offset + consumed, length - consumed, 'ngap-tail')
    coverage.push({
      protocol: 'ngap-tail',
      offset: offset + consumed,
      length: length - consumed,
      status: 'redacted',
    })
    issues.push('ngap-partial-decode')
  }

  return { coverage, issues }
}

/**
 * T61 child port — sanitize a concrete N2 ASN.1 transfer type by schemaTypeId.
 * Does not attempt whole NGAP-PDU decode on opaque SBI bytes.
 */
export function sanitizeN2Transfer(
  schemaTypeId: N2TransferSchemaId,
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  const schema = n2TransferSchema(schemaTypeId)
  if (!schema) {
    maskSpan(collector, intents, packetIndex, offset, length, 'ngap-n2-unknown-schema')
    return {
      coverage: [{
        protocol: 'ngap-n2-unsupported',
        offset,
        length,
        status: 'redacted',
      }],
      issues: [`ngap-n2-unknown-schema:${schemaTypeId}`],
    }
  }
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const dec = decodeAper(buffer, offset, length, schema)
  if (!dec.ok) {
    maskSpan(collector, intents, packetIndex, offset, length, 'ngap-n2-aper-fail')
    coverage.push({ protocol: 'ngap-n2', offset, length, status: 'malformed' })
    issues.push(`ngap-n2-aper-fail:${schemaTypeId}`)
    return { coverage, issues }
  }
  applyTunnelLeaves(buffer, dec.leaves, collector, mapping, intents, packetIndex)
  coverage.push({ protocol: 'ngap-n2', offset, length, status: 'covered' })
  coverage.push({
    protocol: `ngap-n2:${schemaTypeId}`,
    offset,
    length,
    status: 'covered',
  })
  return { coverage, issues }
}

interface IePair {
  readonly id: number
  readonly valueSpan: { bitOffset: number; bitLength: number }
}

function collectIePairs(leaves: readonly DecodedLeaf[]): IePair[] {
  const out: IePair[] = []
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
    if (field === 'id' && typeof leaf.value === 'number') slot.id = leaf.value
    else if (field === 'value') slot.valueSpan = leaf.span
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
  if ((valueSpan.bitOffset & 7) !== 0 || (valueSpan.bitLength & 7) !== 0) {
    maskSpan(
      collector,
      intents,
      packetIndex,
      valueSpan.bitOffset >> 3,
      (valueSpan.bitLength + 7) >> 3,
      'ngap-ie-unaligned',
    )
    coverage.push({
      protocol: 'ngap-ie',
      offset: valueSpan.bitOffset >> 3,
      length: (valueSpan.bitLength + 7) >> 3,
      status: 'redacted',
    })
    issues.push(`ngap-ie-unaligned:${ieId}`)
    return
  }
  const abs = valueSpan.bitOffset >> 3
  const len = valueSpan.bitLength >> 3
  const schema = ngapIeValueSchema(ieId)

  switch (ieId) {
    case NGAP_IE.AMF_UE_NGAP_ID:
      mapUeNgapId(buffer, abs, len, 'amf', AMF_UE_NGAP_ID_TYPE, collector, mapping, intents, packetIndex, coverage, identityScope)
      return
    case NGAP_IE.RAN_UE_NGAP_ID:
      mapUeNgapId(buffer, abs, len, 'ran', RAN_UE_NGAP_ID_TYPE, collector, mapping, intents, packetIndex, coverage, identityScope)
      return
    case NGAP_IE.NAS_PDU:
      sanitizeNasPdu(buffer, abs, len, collector, mapping, intents, packetIndex, coverage, issues)
      return
    case NGAP_IE.CAUSE:
      if (schema) {
        const d = decodeAper(buffer, abs, len, schema)
        coverage.push({
          protocol: 'ngap-cause',
          offset: abs,
          length: len,
          status: d.ok ? 'covered' : 'redacted',
        })
        if (!d.ok) {
          maskSpan(collector, intents, packetIndex, abs, len, 'ngap-cause-bad')
          issues.push('ngap-cause-bad')
        }
      }
      return
    case NGAP_IE.SECURITY_KEY:
      maskSpan(collector, intents, packetIndex, abs, len, 'ngap-security-key')
      coverage.push({ protocol: 'ngap-security-key', offset: abs, length: len, status: 'redacted' })
      return
    case NGAP_IE.TAI:
    case NGAP_IE.USER_LOCATION:
      maskSpan(collector, intents, packetIndex, abs, len, 'ngap-location')
      coverage.push({ protocol: 'ngap-location', offset: abs, length: len, status: 'redacted' })
      return
    case NGAP_IE.FIVE_G_S_TMSI:
      mapOpaqueBytes(buffer, abs, len, 'ngap-5g-s-tmsi', collector, mapping, intents, packetIndex, coverage)
      return
    case NGAP_IE.GUAMI:
      maskSpan(collector, intents, packetIndex, abs, len, 'ngap-guami')
      coverage.push({ protocol: 'ngap-guami', offset: abs, length: len, status: 'redacted' })
      return
    case NGAP_IE.GLOBAL_RAN_NODE_ID:
      mapGlobalRanNodeId(buffer, abs, len, schema!, collector, mapping, intents, packetIndex, coverage, issues)
      return
    case NGAP_IE.UL_NGU_UP_TNL:
      mapNguTunnel(buffer, abs, len, schema!, collector, mapping, intents, packetIndex, coverage, issues)
      return
    case NGAP_IE.SOURCE_TO_TARGET_TRANSPARENT_CONTAINER:
    case NGAP_IE.TARGET_TO_SOURCE_TRANSPARENT_CONTAINER:
      maskSpan(collector, intents, packetIndex, abs, len, 'ngap-transparent-container')
      coverage.push({
        protocol: 'ngap-transparent-container',
        offset: abs,
        length: len,
        status: 'redacted',
      })
      issues.push('ngap-rrc-transparent-mask')
      return
    case NGAP_IE.AMF_NAME:
    case NGAP_IE.RAN_NODE_NAME:
      mapNodeName(buffer, abs, len, collector, mapping, intents, packetIndex, coverage)
      return
    case NGAP_IE.PDU_SESSION_SETUP_ITEM: {
      // Try typed N2 transfer first (same facts as standalone adapter)
      const n2 = sanitizeN2Transfer(
        'ngap.PDUSessionResourceSetupRequestTransfer',
        buffer,
        abs,
        len,
        collector,
        mapping,
        intents,
        packetIndex,
      )
      if (n2 && !n2.issues?.some((i) => i.startsWith('ngap-n2-aper-fail'))) {
        coverage.push(...n2.coverage)
        if (n2.issues) issues.push(...n2.issues)
        return
      }
      if (schema) {
        const d = decodeAper(buffer, abs, len, schema)
        if (d.ok) {
          applyTunnelLeaves(buffer, d.leaves, collector, mapping, intents, packetIndex)
          coverage.push({ protocol: 'ngap-pdu-session', offset: abs, length: len, status: 'covered' })
          return
        }
      }
      maskSpan(collector, intents, packetIndex, abs, len, 'ngap-pdu-session-bad')
      coverage.push({ protocol: 'ngap-pdu-session', offset: abs, length: len, status: 'redacted' })
      issues.push('ngap-pdu-session-bad')
      return
    }
    default:
      maskSpan(collector, intents, packetIndex, abs, len, `ngap-ie-${ieId}`)
      coverage.push({ protocol: 'ngap-ie', offset: abs, length: len, status: 'redacted' })
  }
}

function mapUeNgapId(
  buffer: Uint8Array,
  abs: number,
  len: number,
  role: 'amf' | 'ran',
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
    maskSpan(collector, intents, packetIndex, abs, len, `ngap-${role}-ue-id-bad`)
    coverage.push({ protocol: `ngap-${role}-ue-id`, offset: abs, length: len, status: 'redacted' })
    return
  }
  const original = leaf.value
  const scopePrefix = identityScope && identityScope.length > 0 ? `${identityScope}:` : ''
  const canon =
    canonicalizeIdentity('opaque-id', `ngap-${role}-ue:${scopePrefix}${original}`)
    ?? `ngap-${role}-ue:${scopePrefix}${original}`
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len)
  const lower = type.kind === 'integer' ? type.lower : 0
  const upper = type.kind === 'integer' ? type.upper : 0
  // Retain only the IE slice (not the whole packet) for deferred APER rewrite (V11).
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
        length: len, packetIndex, offset: abs, domain: `ngap-${role}-ue`,
      })
    } catch {
      return createProtocolNeutralMaskFill({
        length: len, packetIndex, offset: abs, domain: `ngap-${role}-ue`,
      })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'ngap', category: 'opaque-id', packetIndex })
  coverage.push({ protocol: `ngap-${role}-ue-id`, offset: abs, length: len, status: 'covered' })
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
  const schema = ngapIeValueSchema(NGAP_IE.NAS_PDU)
  if (!schema) {
    maskSpan(collector, intents, packetIndex, abs, len, 'ngap-nas')
    return
  }
  const dec = decodeAper(buffer, abs, len, schema)
  const leaf = dec.leaves.find((l) => l.value instanceof Uint8Array)
  if (!dec.ok || !leaf || !(leaf.value instanceof Uint8Array)) {
    maskSpan(collector, intents, packetIndex, abs, len, 'ngap-nas-bad')
    coverage.push({ protocol: 'ngap-nas', offset: abs, length: len, status: 'redacted' })
    issues.push('ngap-nas-bad')
    return
  }
  const nasOff = leaf.span.bitOffset >> 3
  const nasLen = leaf.span.bitLength >> 3
  if (looksLikeNas(buffer, nasOff, nasLen)) {
    const nas = sanitizeNas(buffer, nasOff, nasLen, collector, mapping, intents, packetIndex)
    if (nas) {
      coverage.push(...nas.coverage)
      if (nas.issues) issues.push(...nas.issues)
      coverage.push({ protocol: 'ngap-nas', offset: abs, length: len, status: 'covered' })
      return
    }
  }
  maskSpan(collector, intents, packetIndex, nasOff, nasLen, 'ngap-nas-opaque')
  coverage.push({ protocol: 'ngap-nas', offset: abs, length: len, status: 'redacted' })
  issues.push('ngap-nas-unrecognized')
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
  const schema = ngapIeValueSchema(NGAP_IE.RAN_NODE_NAME)!
  const dec = decodeAper(buffer, abs, len, schema)
  const leaf = dec.leaves.find((l) => l.value instanceof Uint8Array)
  if (!dec.ok || !leaf || !(leaf.value instanceof Uint8Array)) {
    maskSpan(collector, intents, packetIndex, abs, len, 'ngap-name-bad')
    coverage.push({ protocol: 'ngap-node-name', offset: abs, length: len, status: 'redacted' })
    return
  }
  const nameOff = leaf.span.bitOffset >> 3
  const nameLen = leaf.span.bitLength >> 3
  let text = ''
  for (let i = 0; i < nameLen; i++) {
    const c = buffer[nameOff + i]!
    if (c < 0x20 || c > 0x7e) {
      maskSpan(collector, intents, packetIndex, nameOff, nameLen, 'ngap-name-bin')
      coverage.push({ protocol: 'ngap-node-name', offset: abs, length: len, status: 'redacted' })
      return
    }
    text += String.fromCharCode(c)
  }
  const canon = canonicalizeIdentity('hostname', text.toLowerCase())
  if (!canon) {
    maskSpan(collector, intents, packetIndex, nameOff, nameLen, 'ngap-name-bad')
    coverage.push({ protocol: 'ngap-node-name', offset: abs, length: len, status: 'redacted' })
    return
  }
  intents?.recordEntityReplacement(packetIndex, nameOff, 'hostname', canon, nameLen)
  collector.addDeferred(nameOff, nameLen, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(nameOff, nameLen, live.map('hostname', canon))
    } catch {
      return createProtocolNeutralMaskFill({
        length: nameLen, packetIndex, offset: nameOff, domain: 'ngap-name',
      })
    }
  }, { fallbackKind: 'text-x', protocol: 'ngap', category: 'hostname', packetIndex })
  coverage.push({ protocol: 'ngap-node-name', offset: abs, length: len, status: 'covered' })
  void mapping
}

function mapGlobalRanNodeId(
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
    maskSpan(collector, intents, packetIndex, abs, len, 'ngap-global-ran-bad')
    coverage.push({ protocol: 'ngap-global-ran-id', offset: abs, length: len, status: 'redacted' })
    issues.push('ngap-global-ran-bad')
    return
  }
  const gnb = dec.leaves.find((l) => l.path.includes('gNB-ID') && typeof l.value === 'number')
  if (gnb && typeof gnb.value === 'number') {
    const canon = canonicalizeIdentity('opaque-id', `ngap-gnb:${gnb.value}`) ?? `ngap-gnb:${gnb.value}`
    const byteOff = gnb.span.bitOffset >> 3
    const byteLen = Math.max(1, (gnb.span.bitLength + 7) >> 3)
    intents?.recordEntityReplacement(packetIndex, byteOff, 'opaque-id', canon, byteLen)
    collector.addDeferred(byteOff, byteLen, ({ mapping: live }) => {
      const alias = live.map('opaque-id', canon)
      return createProtocolNeutralMaskFill({
        length: byteLen, packetIndex, offset: byteOff, domain: `ngap-gnb:${alias}`,
      })
    })
  }
  coverage.push({ protocol: 'ngap-global-ran-id', offset: abs, length: len, status: 'covered' })
  void mapping
}

function mapNguTunnel(
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
    maskSpan(collector, intents, packetIndex, abs, len, 'ngap-ngu-bad')
    coverage.push({ protocol: 'ngap-ngu-tunnel', offset: abs, length: len, status: 'redacted' })
    issues.push('ngap-ngu-bad')
    return
  }
  applyTunnelLeaves(buffer, dec.leaves, collector, mapping, intents, packetIndex)
  coverage.push({ protocol: 'ngap-ngu-tunnel', offset: abs, length: len, status: 'covered' })
}

function mapOpaqueBytes(
  buffer: Uint8Array,
  abs: number,
  len: number,
  domain: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  const schema = ngapIeValueSchema(NGAP_IE.FIVE_G_S_TMSI)
  let off = abs
  let blen = len
  if (schema) {
    const dec = decodeAper(buffer, abs, len, schema)
    const leaf = dec.leaves.find((l) => l.value instanceof Uint8Array)
    if (dec.ok && leaf && leaf.value instanceof Uint8Array) {
      off = leaf.span.bitOffset >> 3
      blen = leaf.span.bitLength >> 3
    }
  }
  let hex = ''
  for (let i = 0; i < Math.min(blen, 8); i++) hex += buffer[off + i]!.toString(16).padStart(2, '0')
  const canon = canonicalizeIdentity('opaque-id', `${domain}:${hex}`) ?? `${domain}:${hex}`
  intents?.recordEntityReplacement(packetIndex, off, 'opaque-id', canon, blen)
  collector.addDeferred(off, blen, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: blen, packetIndex, offset: off, domain: `${domain}:${alias}`,
    })
  })
  coverage.push({ protocol: 'ngap-5g-s-tmsi', offset: abs, length: len, status: 'covered' })
  void mapping
}

function tunnelReceiveEndpoint(
  buffer: Uint8Array,
  leaves: readonly DecodedLeaf[],
): string | undefined {
  for (const leaf of leaves) {
    if (
      leaf.path.includes('transportLayerAddress')
      && typeof leaf.value === 'number'
      && leaf.span.bitLength === 32
    ) {
      const ipOff = leaf.span.bitOffset >> 3
      const ip =
        `${buffer[ipOff]}.${buffer[ipOff + 1]}.${buffer[ipOff + 2]}.${buffer[ipOff + 3]}`
      if (ip !== '0.0.0.0') return ip
    }
  }
  return undefined
}

function applyTunnelLeaves(
  buffer: Uint8Array,
  leaves: readonly DecodedLeaf[],
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const receiveEndpoint = tunnelReceiveEndpoint(buffer, leaves)
  const teidScope = receiveEndpoint ? { receiveEndpoint, plane: 'u' as const } : undefined
  for (const leaf of leaves) {
    if (
      leaf.path.includes('transportLayerAddress')
      && typeof leaf.value === 'number'
      && leaf.span.bitLength === 32
    ) {
      const ipOff = leaf.span.bitOffset >> 3
      const ip =
        `${buffer[ipOff]}.${buffer[ipOff + 1]}.${buffer[ipOff + 2]}.${buffer[ipOff + 3]}`
      if (ip !== '0.0.0.0') {
        intents?.recordEntityReplacement(packetIndex, ipOff, 'ipv4', ip, 4)
        collector.addDeferred(ipOff, 4, ({ mapping: live }) => {
          return new Uint8Array(live.map('ipv4', ip).split('.').map(Number))
        })
      }
    }
    if (leaf.path.includes('gtpTeid') && leaf.value instanceof Uint8Array && leaf.value.length === 4) {
      patchTeid(buffer, leaf.span.bitOffset >> 3, collector, mapping, intents, packetIndex, teidScope)
    }
  }
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
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'ngap')
  collector.addDeferred(offset, length, () => createProtocolNeutralMaskFill({
    length, packetIndex, offset, domain,
  }))
}

/** Test helper: build synthetic NGAP-PDU via T56 encode. */
export function encodeNgapPdu(args: {
  readonly outcome: 'initiatingMessage' | 'successfulOutcome' | 'unsuccessfulOutcome'
  readonly procedureCode: number
  readonly criticality?: 'reject' | 'ignore' | 'notify'
  readonly ies: readonly { id: number; criticality?: 'reject' | 'ignore' | 'notify'; value: Uint8Array }[]
}): Uint8Array | null {
  return encodeAper(
    NGAP_PDU_TYPE,
    {
      alt: args.outcome,
      value: {
        procedureCode: args.procedureCode,
        criticality: args.criticality ?? 'ignore',
        value: args.ies.map((ie) => ({
          id: ie.id,
          criticality: ie.criticality ?? 'reject',
          value: ie.value,
        })),
      },
    },
    4096,
  )
}

export function encodeNgapIeValue(type: AperTypeDesc, value: unknown): Uint8Array | null {
  return encodeAper(type, value, 2048)
}

export function encodeN2Transfer(
  schemaTypeId: N2TransferSchemaId,
  value: unknown,
): Uint8Array | null {
  const schema = n2TransferSchema(schemaTypeId)
  if (!schema) return null
  return encodeAper(schema, value, 2048)
}
