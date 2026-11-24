/**
 * T53 — shared PIDF-LO / geopriv location codec (RFC 4119 / 5491).
 * Coordinates and civic fields always redact; entity/tuple/device IDs scoped map.
 * XXE / DTD forbidden. Used by SIP bodies and other location consumers.
 */

export interface LocationBodySpan {
  readonly offset: number
  readonly length: number
}

export interface LocationBodyOperation {
  readonly span: LocationBodySpan
  readonly action: 'map' | 'redact'
  readonly mappingCategory: string | null
  readonly canonicalText: string
  readonly maskByte: number
}

const MASK = 0x78 // 'x'

/** Element local names whose text is always location content (both levels). */
const LOCATION_ELEMENTS =
  /^(?:pos|position|latitude|longitude|alt|altitude|radius|semiMajorAxis|semiMinorAxis|orientation|height|civicAddress|LOC|A1|A2|A3|A4|A5|A6|PRD|POD|STS|HNO|HNS|LMK|LOC|NAM|PC|BLD|UNIT|FLR|ROOM|PLC|PCN|POBOX|ADDCODE|SEAT|RD|RDSEC|RDBR|RDSUBBR|PRM|POM|country|city|street|streetNumber|postalCode|floor|room|building|method|provided-by|retention-expiry|retransmission-allowed|ruleset|transformation|circle|Ellipse|ArcBand|Sphere|Ellipsoid|Prism|Polygon|LineString|Point|gmlCode|ca:|gml|gmlLoc|gmlName)$/i

const MAP_ELEMENTS: ReadonlyMap<string, string> = new Map([
  ['entity', 'opaque-id'],
  ['tuple', 'opaque-id'],
  ['device', 'opaque-id'],
  ['person', 'person'],
  ['id', 'opaque-id'],
  ['display-name', 'person'],
  ['note', 'opaque-id'],
])

const PIDF_HINT =
  /(?:pidf|geopriv|location-info|civicAddress|gmlCode|presence\b|urn:ietf:params:xml:ns:pidf|urn:ietf:params:xml:ns:pidf:geopriv10)/i

export function looksLikePidfXmlText(text: string): boolean {
  if (text.length < 12) return false
  if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) return true
  return PIDF_HINT.test(text)
}

export function looksLikePidfContentType(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return (
    base === 'application/pidf+xml'
    || base === 'application/pidf-diff+xml'
    || base === 'application/pidf-lo+xml'
    || base === 'application/held+xml'
    || base.includes('pidf')
    || base.includes('geopriv')
  )
}

/**
 * Plan map/redact ops for PIDF-LO / geopriv XML (absolute offsets into `buffer`).
 */
export function buildPidfLoBodyPlan(
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
    issues.push('pidf-xxe-forbidden')
    return { operations: ops, issues }
  }

  // Element text
  const re = /<([A-Za-z][\w:.-]*)(?:\s[^>]*)?>([^<]*)<\/\1>/g
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const rawName = m[1]!
    const local = localName(rawName)
    const value = m[2] ?? ''
    if (value.length === 0) continue
    const valueStartInMatch = m[0]!.indexOf(value)
    if (valueStartInMatch < 0) continue
    const absOff = bodySpan.offset + m.index + valueStartInMatch
    const span = { offset: absOff, length: value.length }

    if (LOCATION_ELEMENTS.test(local) || LOCATION_ELEMENTS.test(rawName)) {
      ops.push({
        span,
        action: 'redact',
        mappingCategory: null,
        canonicalText: value,
        maskByte: MASK,
      })
      continue
    }
    // Numeric-looking coordinate leftovers in unknown elements
    if (/^-?\d+(?:\.\d+)?(?:\s+-?\d+(?:\.\d+)?)+$/.test(value.trim())) {
      ops.push({
        span,
        action: 'redact',
        mappingCategory: null,
        canonicalText: value,
        maskByte: MASK,
      })
      issues.push('pidf-coordinate-masked')
      continue
    }
    const cat = MAP_ELEMENTS.get(local.toLowerCase())
    if (!cat) continue
    ops.push({
      span,
      action: 'map',
      mappingCategory: cat === 'opaque-id' ? 'opaque-id' : cat,
      canonicalText: cat === 'opaque-id' ? `pidf:${local}:${value}` : value,
      maskByte: MASK,
    })
  }

  // Attribute values: entity=, id= on presence/tuple/device
  const attrRe = /\b(entity|id)\s*=\s*"([^"]*)"/gi
  let am: RegExpExecArray | null
  while ((am = attrRe.exec(text)) !== null) {
    const value = am[2] ?? ''
    if (value.length === 0) continue
    const absOff = bodySpan.offset + am.index + am[0]!.lastIndexOf(`"${value}"`) + 1
    ops.push({
      span: { offset: absOff, length: value.length },
      action: 'map',
      mappingCategory: 'opaque-id',
      canonicalText: `pidf-attr:${value}`,
      maskByte: MASK,
    })
  }

  // Comments / PI content — mask interiors
  const commentRe = /<!--([\s\S]*?)-->/g
  let cm: RegExpExecArray | null
  while ((cm = commentRe.exec(text)) !== null) {
    const inner = cm[1] ?? ''
    if (inner.length === 0) continue
    const absOff = bodySpan.offset + cm.index + 4
    ops.push({
      span: { offset: absOff, length: inner.length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: MASK,
    })
  }

  if (ops.length === 0 && looksLikePidfXmlText(text)) {
    // Fail-closed: claimed PIDF but no field ops — mask whole body
    ops.push({
      span: { offset: bodySpan.offset, length: bodySpan.length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: MASK,
    })
    issues.push('pidf-unparsed-mask')
  }

  return { operations: ops, issues }
}

function localName(raw: string): string {
  const i = raw.indexOf(':')
  return i >= 0 ? raw.slice(i + 1) : raw
}
