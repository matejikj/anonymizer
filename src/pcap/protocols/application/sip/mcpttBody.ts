/**
 * T37 — MCPTT/MCData/MCVideo SIP XML bodies (3GPP mcptt-info / affiliation / location).
 * Element text spans: user/group URIs map; location always redact; indicators preserve.
 */

import type { ByteSpan } from './types'
import { decodeLatin1Span } from './bytes'
import { SIP_REDACT_MASK_BYTE } from './redactPlan'

export function looksLikeMcpttBody(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return (
    base.includes('vnd.3gpp.mcptt')
    || base.includes('vnd.3gpp.mcdata')
    || base.includes('vnd.3gpp.mcvideo')
    || base === 'application/resource-lists+xml'
  )
}

export function looksLikeDtmfRelayBody(contentType: string | null): boolean {
  if (!contentType) return false
  return contentType.trim().split(';')[0]?.trim().toLowerCase() === 'application/dtmf-relay'
}

export function looksLikeDialogInfoBody(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return base === 'application/dialog-info+xml' || base === 'application/media_control+xml'
}

export function looksLikeSipfragBody(contentType: string | null): boolean {
  if (!contentType) return false
  return contentType.trim().split(';')[0]?.trim().toLowerCase() === 'message/sipfrag'
}

export function looksLikeIsupBody(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return base === 'application/isup' || base === 'application/vnd.etsi.isup'
}

export interface McpttBodyOperation {
  readonly span: ByteSpan
  readonly action: 'map' | 'redact'
  readonly mappingCategory: string | null
  readonly canonicalText: string
  readonly maskByte: number
}

/** Local-name → category; location* always redact regardless. */
const MAP_ELEMENTS: ReadonlyMap<string, string> = new Map([
  ['mcptt-request-uri', 'sip-user'],
  ['mcptt-calling-user-id', 'sip-user'],
  ['mcptt-called-party-id', 'sip-user'],
  ['mcptt-calling-group-id', 'hostname'],
  ['mcptt-client-id', 'opaque-id'],
  ['mcdata-request-uri', 'sip-user'],
  ['mcdata-calling-user-id', 'sip-user'],
  ['entry', 'sip-user'], // resource-lists
  ['display-name', 'person'],
])

const LOCATION_HINT = /location|geoloc|ecgi|civic|coord|latitude|longitude|pidf/i

/** Analysis-preserving MCPTT indicators (not identity); no map/mask ops on text. */
const PRESERVE_ELEMENT_LOCAL: ReadonlySet<string> = new Set([
  'mcptt-request-type',
  'mcptt-call-type',
  'mcptt-emergency-ind',
  'mcptt-imminent-peril-ind',
  'mcptt-priority',
  'floor-priority',
  'request-type',
])

/**
 * Plan map/redact ops for MCPTT-family XML. Unknown / vendor text inside location → redact.
 * Structural tags and priority/emergency enums left untouched (no ops).
 */
export function buildMcpttBodyPlan(
  buffer: Uint8Array,
  bodySpan: ByteSpan,
): readonly McpttBodyOperation[] {
  const ops: McpttBodyOperation[] = []
  const text = decodeLatin1Span(buffer, bodySpan)
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
    const span: ByteSpan = { offset: absOff, length: value.length }

    if (LOCATION_HINT.test(local) || LOCATION_HINT.test(rawName)) {
      ops.push({
        span,
        action: 'redact',
        mappingCategory: null,
        canonicalText: value,
        maskByte: SIP_REDACT_MASK_BYTE,
      })
      continue
    }
    if (PRESERVE_ELEMENT_LOCAL.has(local.toLowerCase())) {
      continue
    }
    const cat = MAP_ELEMENTS.get(local.toLowerCase())
    if (!cat) {
      ops.push({
        span,
        action: 'redact',
        mappingCategory: null,
        canonicalText: value,
        maskByte: SIP_REDACT_MASK_BYTE,
      })
      continue
    }
    const mappedCat =
      local.toLowerCase() === 'mcptt-calling-group-id'
        ? 'hostname'
        : categoryForUriValue(value, cat)
    ops.push({
      span,
      action: 'map',
      mappingCategory: mappedCat,
      canonicalText: value,
      maskByte: SIP_REDACT_MASK_BYTE,
    })
  }
  return ops
}

function categoryForUriValue(value: string, fallback: string): string {
  const v = value.trim()
  if (/^sip:/i.test(v) || /^tel:/i.test(v)) {
    // Prefer phone when tel: or digits-heavy user part
    if (/^tel:/i.test(v) || /sip:\+?\d{6,}@/i.test(v)) return 'sip-phone'
    return 'sip-user'
  }
  if (/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v)) return 'hostname'
  return fallback
}

/** DTMF-relay: mask Signal= token; preserve Duration=. */
export function buildDtmfRelayBodyPlan(
  buffer: Uint8Array,
  bodySpan: ByteSpan,
): readonly McpttBodyOperation[] {
  const ops: McpttBodyOperation[] = []
  const text = decodeLatin1Span(buffer, bodySpan)
  const re = /^Signal=\s*([0-9A-D*#])\s*$/gim
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const token = m[1]!
    const absOff = bodySpan.offset + m.index + m[0]!.indexOf(token)
    ops.push({
      span: { offset: absOff, length: token.length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: token,
      maskByte: 0x58, // 'X'
    })
  }
  return ops
}

/** dialog-info / media_control: map identity-looking attribute/element values. */
export function buildDialogInfoBodyPlan(
  buffer: Uint8Array,
  bodySpan: ByteSpan,
): readonly McpttBodyOperation[] {
  // Reuse MCPTT-style element walker with dialog-info names
  const ops: McpttBodyOperation[] = []
  const text = decodeLatin1Span(buffer, bodySpan)
  const re = /<(?:[\w-]+:)?(identity|remote|local|target|display)(?:\s[^>]*)?>([^<]+)<\/(?:[\w-]+:)?\1>/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const value = m[2]!
    const absOff = bodySpan.offset + m.index + m[0]!.indexOf(value)
    const name = m[1]!.toLowerCase()
    const cat = name === 'display' ? 'person' : categoryForUriValue(value, 'sip-user')
    ops.push({
      span: { offset: absOff, length: value.length },
      action: 'map',
      mappingCategory: cat,
      canonicalText: value,
      maskByte: SIP_REDACT_MASK_BYTE,
    })
  }
  return ops
}
