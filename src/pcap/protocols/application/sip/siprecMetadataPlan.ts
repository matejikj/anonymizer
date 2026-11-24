/**
 * T02 — SIPREC rs-metadata+xml planner (RFC 7865 / 7866).
 * Namespace-aware bounded walk: map participant AoRs, session/group IDs, absolute times;
 * forbid DTD/XXE; mask unknown text/attrs. Shared by discovery and plan via bodyOperations.
 */

import {
  isWhitespaceSpan,
  isXmlnsAttr,
  parseBoundedXml,
  spanText,
  type XmlElement,
  type XmlNode,
  type XmlSpan,
} from '../csta/boundedXml.ts'

export interface SiprecBodySpan {
  readonly offset: number
  readonly length: number
}

export interface SiprecBodyOperation {
  readonly span: SiprecBodySpan
  readonly action: 'map' | 'redact'
  readonly mappingCategory: string | null
  readonly canonicalText: string
  readonly maskByte: number
}

const MASK = 0x23 // '#' — same as SIP_REDACT_MASK_BYTE

const TIME_ELEMENTS = /^(?:associate-time|disassociate-time|start|end|timestamp)$/i

/**
 * Plan map/redact ops for a SIPREC metadata XML span (absolute offsets into `buffer`).
 */
export function buildSiprecMetadataPlan(
  buffer: Uint8Array,
  bodySpan: SiprecBodySpan,
): { readonly operations: readonly SiprecBodyOperation[]; readonly issues: readonly string[] } {
  const ops: SiprecBodyOperation[] = []
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
    issues.push('siprec-xxe-forbidden')
    return { operations: ops, issues }
  }

  const parsed = parseBoundedXml(text)
  if (!parsed.complete) {
    ops.push({
      span: { offset: bodySpan.offset, length: bodySpan.length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: MASK,
    })
    issues.push('siprec-xml-incomplete', ...parsed.issues)
    return { operations: ops, issues }
  }

  const seen = new Set<string>()
  const emitRedact = (rel: XmlSpan): void => {
    const length = rel.end - rel.start
    if (length <= 0) return
    const key = `${rel.start}:${rel.end}`
    if (seen.has(key)) return
    seen.add(key)
    ops.push({
      span: { offset: bodySpan.offset + rel.start, length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: MASK,
    })
  }

  const emitMap = (rel: XmlSpan, category: string, canonical: string): void => {
    const length = rel.end - rel.start
    if (length <= 0) return
    const key = `${rel.start}:${rel.end}`
    if (seen.has(key)) return
    seen.add(key)
    ops.push({
      span: { offset: bodySpan.offset + rel.start, length },
      action: 'map',
      mappingCategory: category,
      canonicalText: canonical,
      maskByte: MASK,
    })
  }

  const walk = (node: XmlNode, parentLocal: string | null): void => {
    if (node.kind === 'comment' || node.kind === 'pi' || node.kind === 'doctype') return

    if (node.kind === 'text' || node.kind === 'cdata') {
      const content: XmlSpan = node.kind === 'cdata' ? node.content : node.span
      if (isWhitespaceSpan(text, content)) return
      if (parentLocal && TIME_ELEMENTS.test(parentLocal)) {
        emitMap(content, 'timestamp', spanText(text, content).trim())
        return
      }
      if (parentLocal === 'name') {
        emitMap(content, 'person', spanText(text, content).trim())
        return
      }
      // Unknown text — mask (fail-closed).
      emitRedact(content)
      return
    }

    const el = node as XmlElement
    for (const attr of el.attrs) {
      if (isXmlnsAttr(attr.localName, attr.rawName)) continue
      const value = spanText(text, attr.value).trim()
      const mapped = mapSiprecAttr(attr.localName, value)
      if (mapped) {
        emitMap(attr.value, mapped.category, mapped.canonical)
      } else {
        emitRedact(attr.value)
      }
    }

    for (const child of el.children) {
      walk(child, el.localName)
    }
  }

  for (const root of parsed.roots) {
    walk(root, null)
  }

  issues.push('siprec-xml-planned')
  return { operations: ops, issues }
}

function mapSiprecAttr(
  localName: string,
  value: string,
): { category: string; canonical: string } | null {
  switch (localName) {
    case 'aor':
      if (/^tel:/i.test(value) || /^\+?\d{6,}$/.test(value)) {
        return { category: 'sip-phone', canonical: value }
      }
      return { category: 'user-id', canonical: value }
    case 'session_id':
    case 'session-id':
      return { category: 'opaque-id', canonical: `siprec-session:${value}` }
    case 'participant_id':
    case 'participant-id':
      return { category: 'opaque-id', canonical: `siprec-participant:${value}` }
    case 'group_id':
    case 'group-id':
      return { category: 'opaque-id', canonical: `siprec-group:${value}` }
    case 'stream_id':
    case 'stream-id':
      return { category: 'opaque-id', canonical: `siprec-stream:${value}` }
    default:
      return null
  }
}
