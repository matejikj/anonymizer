/**
 * T49 — CSTA Annex J / bare XML sanitizer (TCP content probe).
 * ASN.1 ROSE Phase III: identify + fail-closed mask (no offset guessing).
 */

import type { PatchCollector } from './PatchCollector.ts'
import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { AppLayerResult } from './types.ts'
import { computeFixedLengthAsciiBytes, patchFixedLengthAscii } from './textPatch.ts'
import { redactXmlTextBytes, XML_TEXT_REDACT_BYTE } from './httpBody.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import {
  buildCstaXmlBodyPlan,
  looksLikeBareCstaXml,
  looksLikeCstaAnnexJ,
  parseAnnexJUnits,
} from '../protocols/application/csta/index.ts'
import { extractCstaServiceFacts } from '../protocols/application/csta/cstaXmlFacts.ts'
import {
  protocolGraphCaptureGeneration,
  tcpTransportSessionKey,
} from './protocolGraphState.ts'
import { cstaMonitorGraphForTransport } from './csta/cstaMonitorGraph.ts'

export function isCstaPortHint(_src: number, _dst: number): boolean {
  // No IANA-fixed CSTA port — content probe only.
  return false
}

export function looksLikeCsta(
  buffer: Uint8Array,
  offset: number,
  length: number,
): boolean {
  if (looksLikeCstaAnnexJ(buffer, offset, length)) return true
  if (looksLikeBareCstaXml(buffer, offset, length)) return true
  // BER SEQUENCE start — ASN.1 CSTA without XML: identify-only claim via sanitize
  if (length >= 4 && buffer[offset] === 0x30) {
    // Heuristic: not TLS (0x16) / not HTTP; leave weak — only claim if port hint later
    return false
  }
  return false
}

export function looksLikeCstaAsn1(
  buffer: Uint8Array,
  offset: number,
  length: number,
): boolean {
  // Conservative: APPLICATION/CONTEXT tags common in ROSE — require length + not XML
  if (length < 8) return false
  const b0 = buffer[offset]!
  if (b0 !== 0x30 && b0 !== 0x61 && b0 !== 0xa1) return false
  const head = new TextDecoder('latin1').decode(buffer.subarray(offset, offset + Math.min(length, 8)))
  if (head.includes('<')) return false
  return true
}

export function sanitizeCsta(
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
  /** Optional L3 endpoints for PBX/session scope (V17). */
  endpoints?: { readonly srcIp?: string; readonly dstIp?: string },
): AppLayerResult | null {
  const identityScope = `csta:${endpoints?.srcIp ?? '?'}:${srcPort}>${endpoints?.dstIp ?? '?'}:${dstPort}`
  const transportSessionKey = tcpTransportSessionKey({
    srcIp: endpoints?.srcIp,
    dstIp: endpoints?.dstIp,
    srcPort,
    dstPort,
  })
  if (looksLikeCstaAnnexJ(buffer, offset, length)) {
    return sanitizeAnnexJ(
      buffer,
      offset,
      length,
      collector,
      mapping,
      packetIndex,
      intents,
      identityScope,
      transportSessionKey,
    )
  }
  if (looksLikeBareCstaXml(buffer, offset, length)) {
    return sanitizeXmlSpan(
      buffer,
      offset,
      length,
      collector,
      mapping,
      packetIndex,
      intents,
      true,
      identityScope,
      transportSessionKey,
    )
  }
  // ASN.1 baseline: fail-closed mask with explicit protocol id
  if (looksLikeCstaAsn1(buffer, offset, length)) {
    maskRange(collector, intents, packetIndex, offset, length, 'csta-asn1')
    return {
      coverage: [
        { protocol: 'csta-asn1', offset, length, status: 'redacted' },
        { protocol: 'csta', offset, length, status: 'covered' },
      ],
      issues: ['csta-asn1-mask-only'],
    }
  }
  return null
}

function sanitizeAnnexJ(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  identityScope: string,
  transportSessionKey: string,
): AppLayerResult {
  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const units = parseAnnexJUnits(buffer, offset, length)
  let cursor = offset
  for (const u of units) {
    coverage.push({
      protocol: 'csta',
      offset: u.headerOffset,
      length: u.headerLength,
      status: 'covered',
    })
    const body = sanitizeXmlSpan(
      buffer,
      u.bodyOffset,
      u.bodyLength,
      collector,
      mapping,
      packetIndex,
      intents,
      false,
      identityScope,
      transportSessionKey,
    )
    coverage.push(...body.coverage)
    if (body.issues) issues.push(...body.issues)
    cursor = u.bodyOffset + u.bodyLength
  }
  if (cursor < offset + length) {
    // Trailing incomplete / unknown — mask
    maskRange(collector, intents, packetIndex, cursor, offset + length - cursor, 'csta-tail')
    coverage.push({
      protocol: 'csta-body',
      offset: cursor,
      length: offset + length - cursor,
      status: 'redacted',
    })
  }
  coverage.push({ protocol: 'csta', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeXmlSpan(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  wrapParent: boolean,
  identityScope: string,
  transportSessionKey?: string,
): AppLayerResult {
  const invokeGen = protocolGraphCaptureGeneration()
  const { operations, issues } = buildCstaXmlBodyPlan(
    buffer,
    { offset, length },
    identityScope,
    invokeGen,
  )
  const facts = extractCstaServiceFacts(buffer, { offset, length })
  if (facts && transportSessionKey) {
    cstaMonitorGraphForTransport(mapping, transportSessionKey).note(facts, packetIndex)
  }
  const coverage: AppLayerResult['coverage'] = [
    { protocol: 'csta-xml', offset, length, status: 'covered' },
  ]
  for (const op of operations) {
    if (op.action === 'redact') {
      redactXmlSpan(
        collector,
        intents,
        packetIndex,
        op.span.offset,
        op.span.length,
        'csta-secret',
        op.maskByte,
      )
      coverage.push({
        protocol: 'csta-secret',
        offset: op.span.offset,
        length: op.span.length,
        status: 'redacted',
      })
      continue
    }
    const cat = (op.mappingCategory ?? 'opaque-id') as 'opaque-id' | 'user-id' | 'hostname' | 'sip-phone' | 'person'
    const raw = new TextDecoder('latin1').decode(
      buffer.subarray(op.span.offset, op.span.offset + op.span.length),
    )
    const canon =
      canonicalizeIdentity(cat === 'sip-phone' ? 'sip-phone' : cat, op.canonicalText) ?? op.canonicalText
    const constraint = { kind: 'text-ascii' as const, byteLength: op.span.length }
    intents?.recordEntityReplacement(
      packetIndex,
      op.span.offset,
      cat,
      canon,
      op.span.length,
      constraint,
      raw,
    )
    collector.addDeferred(
      op.span.offset,
      op.span.length,
      ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(
            op.span.offset,
            op.span.length,
            live.aliasFor(cat, canon, constraint, raw),
          )
        } catch {
          return computeFixedLengthAsciiBytes(
            op.span.offset,
            op.span.length,
            '',
            op.maskByte,
          )
        }
      },
      { fallbackKind: 'text-x', protocol: 'csta', category: cat, packetIndex },
    )
    coverage.push({
      protocol: 'csta-device',
      offset: op.span.offset,
      length: op.span.length,
      status: 'covered',
    })
  }
  if (wrapParent) {
    coverage.push({ protocol: 'csta', offset, length, status: 'covered' })
  }
  void mapping
  return { coverage, issues: [...issues] }
}

function redactXmlSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
  padByte: number = XML_TEXT_REDACT_BYTE,
): void {
  if (length <= 0) return
  try {
    redactXmlTextBytes(collector, intents, packetIndex, offset, length, domain, 'csta', padByte)
  } catch {
    try {
      patchFixedLengthAscii(collector, offset, length, '', padByte)
      intents?.recordMaskRange(packetIndex, offset, length, domain, 'csta')
    } catch {
      /* overlap */
    }
  }
}

function maskRange(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  redactXmlSpan(collector, intents, packetIndex, offset, length, domain)
}
