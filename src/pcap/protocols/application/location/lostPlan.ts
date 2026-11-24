/**
 * T53 — LoST (RFC 5222) location-to-service XML planner.
 * Geometry / civic / displayName / URI endpoints redact or scoped map; IDs map.
 */

import {
  buildPidfLoBodyPlan,
  type LocationBodyOperation,
  type LocationBodySpan,
} from './pidfLoPlan.ts'

const MASK = 0x78

const LOST_HINT =
  /(?:findService|listServices|listServicesByLocation|getServiceBoundary|locationResponse|serviceBoundary|displayName|urn:oasis:names:tc:emergency:lost|locationValidation)/i

/** Always redact (location-derived or contact content). */
const REDACT_ELEMENTS =
  /^(?:displayName|serviceBoundary|location|civicAddress|geodetic|pos|point|polygon|circle|uri|serviceUri|serviceNumber|expires|path|locationValidation|invalid|valid|error|message|sourceId)$/i

const MAP_ELEMENTS: ReadonlyMap<string, string> = new Map([
  ['requestid', 'opaque-id'],
  ['messageid', 'opaque-id'],
  ['service', 'opaque-id'],
  ['serviceurn', 'opaque-id'],
])

export function looksLikeLostXmlText(text: string): boolean {
  if (text.length < 12) return false
  if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) return true
  return LOST_HINT.test(text)
}

export function looksLikeLostContentType(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return (
    base === 'application/lost+xml'
    || base === 'application/lost+xml; charset=utf-8'
    || base.includes('lost+xml')
  )
}

export function buildLostBodyPlan(
  buffer: Uint8Array,
  bodySpan: LocationBodySpan,
): { readonly operations: readonly LocationBodyOperation[]; readonly issues: readonly string[] } {
  const ops: LocationBodyOperation[] = []
  const issues: string[] = []
  const text = new TextDecoder('latin1').decode(
    buffer.subarray(bodySpan.offset, bodySpan.offset + bodySpan.length),
  )

  if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) {
    ops.push({
      span: { offset: bodySpan.offset, length: bodySpan.length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: MASK,
    })
    issues.push('lost-xxe-forbidden')
    return { operations: ops, issues }
  }

  // Nested PIDF-like geometry via shared redaction for coordinate-looking values
  const nested = buildPidfLoBodyPlan(buffer, bodySpan)
  for (const op of nested.operations) {
    if (op.action === 'redact') ops.push(op)
  }
  for (const i of nested.issues) {
    if (i.includes('xxe')) issues.push(i.replace('pidf', 'lost'))
  }

  const re = /<([A-Za-z][\w:.-]*)(?:\s[^>]*)?>([^<]*)<\/\1>/g
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const rawName = m[1]!
    const local = rawName.includes(':') ? rawName.slice(rawName.indexOf(':') + 1) : rawName
    const value = m[2] ?? ''
    if (value.length === 0) continue
    const valueStartInMatch = m[0]!.indexOf(value)
    if (valueStartInMatch < 0) continue
    const absOff = bodySpan.offset + m.index + valueStartInMatch
    const span = { offset: absOff, length: value.length }

    if (REDACT_ELEMENTS.test(local)) {
      // Skip if already covered by nested pidf plan at same offset
      if (ops.some((o) => o.span.offset === span.offset && o.span.length === span.length)) continue
      ops.push({
        span,
        action: 'redact',
        mappingCategory: null,
        canonicalText: value,
        maskByte: MASK,
      })
      continue
    }
    const cat = MAP_ELEMENTS.get(local.toLowerCase())
    if (!cat) continue
    if (ops.some((o) => o.span.offset === span.offset && o.span.length === span.length)) continue
    // Preserve standard urn:service:sos* allowlist as structural (no op)
    if (local.toLowerCase() === 'service' || local.toLowerCase() === 'serviceurn') {
      if (/^urn:service:sos(?:\.[\w.-]+)?$/i.test(value.trim())) continue
    }
    ops.push({
      span,
      action: 'map',
      mappingCategory: 'opaque-id',
      canonicalText: `lost:${local}:${value}`,
      maskByte: MASK,
    })
  }

  if (ops.length === 0 && looksLikeLostXmlText(text)) {
    ops.push({
      span: { offset: bodySpan.offset, length: bodySpan.length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: MASK,
    })
    issues.push('lost-unparsed-mask')
  }

  return { operations: ops, issues }
}
