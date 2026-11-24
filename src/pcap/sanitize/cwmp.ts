/**
 * T55 — CWMP (TR-069) SOAP sanitizer: apply soapPlan ops; HTTP body / content-probe entry.
 */

import type { PatchCollector } from './PatchCollector.ts'
import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { computeFixedLengthAsciiBytes, patchFixedLengthAscii } from './textPatch.ts'
import { redactXmlTextBytes, XML_TEXT_REDACT_BYTE } from './httpBody.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import {
  buildCwmpSoapBodyPlan,
  looksLikeCwmpContentType,
  looksLikeCwmpSoapText,
} from '../protocols/application/cwmp/soapPlan.ts'

/** Common ACS / CPE management port (TR-069). */
export const CWMP_TCP_PORTS = new Set([7547, 30005])

export function isCwmpPortHint(src: number, dst: number): boolean {
  return CWMP_TCP_PORTS.has(src) || CWMP_TCP_PORTS.has(dst)
}

export function looksLikeCwmp(
  buffer: Uint8Array,
  offset: number,
  length: number,
): boolean {
  if (length < 24) return false
  const head = new TextDecoder('latin1').decode(
    buffer.subarray(offset, offset + Math.min(length, 512)),
  )
  return looksLikeCwmpSoapText(head)
}

export function sanitizeCwmp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeCwmp(buffer, offset, length)) return null
  return sanitizeCwmpSoapBody(buffer, offset, length, collector, mapping, intents, packetIndex)
}

/**
 * Apply CWMP SOAP plan to an absolute body span (HTTP child or bare SOAP).
 */
export function sanitizeCwmpSoapBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult {
  const { operations, issues } = buildCwmpSoapBodyPlan(buffer, { offset, length })
  const coverage: LayerCoverage[] = [
    { protocol: 'cwmp', offset, length, status: 'covered' },
  ]

  if (issues.includes('cwmp-xxe-forbidden')) {
    maskRange(collector, intents, packetIndex, offset, length, 'cwmp-xxe')
    coverage.push({ protocol: 'cwmp-body', offset, length, status: 'malformed' })
    return { coverage, issues: [...issues] }
  }

  if (operations.length === 0 && issues.includes('cwmp-not-matched')) {
    maskRange(collector, intents, packetIndex, offset, length, 'cwmp-unverified')
    coverage.push({ protocol: 'cwmp-body', offset, length, status: 'redacted' })
    return { coverage, issues: ['cwmp-body-masked'] }
  }

  for (const op of operations) {
    if (op.action === 'preserve') {
      coverage.push({
        protocol: 'cwmp',
        offset: op.span.offset,
        length: op.span.length,
        status: 'covered',
      })
      continue
    }
    if (op.action === 'redact') {
      maskRange(collector, intents, packetIndex, op.span.offset, op.span.length, 'cwmp-secret')
      coverage.push({
        protocol: 'cwmp-secret',
        offset: op.span.offset,
        length: op.span.length,
        status: 'redacted',
      })
      continue
    }
    const wire = new TextDecoder('latin1').decode(
      buffer.subarray(op.span.offset, op.span.offset + op.span.length),
    )
    mapAscii(
      op.span.offset,
      op.span.length,
      wire,
      op.canonicalText,
      (op.mappingCategory ?? 'opaque-id') as MapCategory,
      collector,
      mapping,
      intents,
      packetIndex,
    )
    coverage.push({
      protocol: 'cwmp-id',
      offset: op.span.offset,
      length: op.span.length,
      status: 'covered',
    })
  }

  coverage.push({ protocol: 'cwmp-soap', offset, length, status: 'covered' })
  return { coverage, issues: [...issues] }
}

export function cwmpSoapEligible(contentType: string | null, bodyText: string): boolean {
  return looksLikeCwmpSoapText(bodyText) && (
    looksLikeCwmpContentType(contentType)
    || contentType === null
    || looksLikeCwmpSoapText(bodyText)
  )
}

type MapCategory = 'opaque-id' | 'ipv4' | 'mac' | 'hostname' | 'user-id'

function mapAscii(
  offset: number,
  length: number,
  wire: string,
  canonicalHint: string,
  category: MapCategory,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  void mapping
  if (length <= 0 || wire.length === 0) return
  const mapCat =
    category === 'ipv4' || category === 'mac' || category === 'hostname'
      ? category
      : 'opaque-id'
  const seed = mapCat === 'opaque-id' ? canonicalHint : wire
  const canon = canonicalizeIdentity(mapCat, seed) ?? seed
  const constraint = { kind: 'text-ascii' as const, byteLength: length }
  intents?.recordEntityReplacement(packetIndex, offset, mapCat, canon, length, constraint, wire)
  try {
    collector.addDeferred(
      offset,
      length,
      ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(
            offset,
            length,
            live.aliasFor(mapCat, canon, constraint, wire),
          )
        } catch {
          return computeFixedLengthAsciiBytes(offset, length, '', XML_TEXT_REDACT_BYTE)
        }
      },
      { fallbackKind: 'text-x', protocol: 'cwmp', category: mapCat, packetIndex },
    )
  } catch {
    /* overlap */
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
  if (length <= 0) return
  try {
    redactXmlTextBytes(
      collector,
      intents,
      packetIndex,
      offset,
      length,
      domain,
      'cwmp',
      XML_TEXT_REDACT_BYTE,
    )
  } catch {
    try {
      patchFixedLengthAscii(collector, offset, length, '', XML_TEXT_REDACT_BYTE)
      intents?.recordMaskRange(packetIndex, offset, length, domain, 'cwmp')
    } catch {
      /* overlap */
    }
  }
}
