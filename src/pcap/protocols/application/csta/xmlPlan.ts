/**
 * T49 — CSTA XML / uaCSTA body planner (ECMA-323 subset).
 * Bounded XML tokenizer; inherited secret disposition; unknown content/attrs masked.
 */

import {
  isWhitespaceSpan,
  isXmlnsAttr,
  parseBoundedXml,
  spanText,
  type XmlElement,
  type XmlNode,
  type XmlSpan,
} from './boundedXml.ts'

export interface CstaBodySpan {
  readonly offset: number
  readonly length: number
}

export interface CstaBodyOperation {
  readonly span: CstaBodySpan
  readonly action: 'map' | 'redact'
  /** Mapping category string (opaque-id / phone / user-id / hostname / person). */
  readonly mappingCategory: string | null
  readonly canonicalText: string
  readonly maskByte: number
}

const MASK = 0x78 // 'x' — length-preserving; distinct from SIP 0x23 for CSTA-local redacts

/** Identity-bearing element local names (ECMA-323 / common vendor). */
const MAP_ELEMENTS: ReadonlyMap<string, string> = new Map([
  ['deviceid', 'opaque-id'],
  ['callingdevice', 'opaque-id'],
  ['calleddevice', 'opaque-id'],
  ['alertingdevice', 'opaque-id'],
  ['calleddirectorynumber', 'opaque-id'],
  ['associateddevice', 'opaque-id'],
  ['redirectingdevice', 'opaque-id'],
  ['lastredirectiondevice', 'opaque-id'],
  ['subjectdevicedeviceidentifier', 'opaque-id'],
  ['callid', 'opaque-id'],
  ['connectionid', 'opaque-id'],
  ['monitorcrossrefid', 'opaque-id'],
  ['invokeid', 'opaque-id'],
  ['correlatorData', 'opaque-id'],
  ['correlatordata', 'opaque-id'],
  ['agentid', 'user-id'],
  ['acdgroup', 'opaque-id'],
  ['displayname', 'person'],
  ['deviceidentifier', 'opaque-id'],
])

const SECRET_ELEMENTS =
  /^(?:userdata|privatedata|accountinfo|password|pin|auth(?:entication)?|bearer|token|digits|dtmf|recordinguri|voicemailuri)$/i

const LOCATION_ELEMENTS = /^(?:locationinfo|location|civic|gps|geodetic|pidf)/i

/** Structural SOAP/CSTA wrappers whose direct text is never identity content. */
const STRUCTURAL_ELEMENTS =
  /^(?:makecall|answercall|clearconnection|holdcall|retrievecall|transfercall|conferencecall|monitorstart|monitorstop|deliveredevent|establishedevent|connectionclearedevent|originatedevent|divertedevent|envelope|header|body|makecallresponse|monitorstartresponse)$/i

const CSTA_SERVICE_HINT =
  /(?:MakeCall|AnswerCall|ClearConnection|HoldCall|RetrieveCall|TransferCall|ConferenceCall|MonitorStart|MonitorStop|DeliveredEvent|EstablishedEvent|ConnectionClearedEvent|OriginatedEvent|DivertedEvent|csta:|http:\/\/www\.ecma-international\.org\/standards\/ecma-323)/i

export function looksLikeCstaXmlText(text: string): boolean {
  if (text.length < 16) return false
  if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) return true // still "like" for reject path
  return CSTA_SERVICE_HINT.test(text) || /<(?:[\w.-]+:)?(?:MakeCall|MonitorStart|deviceID)\b/i.test(text)
}

/**
 * uaCSTA identity namespace: scoped by outer SIP dialog (Call-ID), never merged with direct CSTA TCP
 * or with another SIP session that happens to reuse the same CSTA callID string.
 */
export function cstaIdentityScopeForUaCsta(sipCallId: string | null | undefined): string {
  const id = sipCallId?.trim()
  if (id && id.length > 0) return `uacsta:sip:${id}`
  return 'uacsta:unknown-dialog'
}

export function looksLikeCstaContentType(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return (
    base === 'application/csta+xml'
    || base === 'application/x-csta+xml'
    || base === 'text/xml'
    || base === 'application/xml'
    || base.includes('csta')
  )
}

/**
 * Plan map/redact ops for a CSTA XML span (absolute offsets into `buffer`).
 * Call IDs are namespaced in canonical form so they never merge with SIP Call-ID.
 */
export function buildCstaXmlBodyPlan(
  buffer: Uint8Array,
  bodySpan: CstaBodySpan,
  /** V17/T49 — PBX/transport session scope so callIDs of two systems never merge. */
  identityScope?: string,
  /** R08/T49 — capture generation so invoke IDs do not merge after session dispose/reconnect. */
  invokeCorrelationGeneration?: string,
): { readonly operations: readonly CstaBodyOperation[]; readonly issues: readonly string[] } {
  const ops: CstaBodyOperation[] = []
  const issues: string[] = []
  const text = new TextDecoder('latin1').decode(
    buffer.subarray(bodySpan.offset, bodySpan.offset + bodySpan.length),
  )
  const pbxScope = identityScope && identityScope.length > 0 ? identityScope : 'default'
  const invokeGen =
    invokeCorrelationGeneration && invokeCorrelationGeneration.length > 0
      ? invokeCorrelationGeneration
      : '0'

  if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) {
    ops.push({
      span: { offset: bodySpan.offset, length: bodySpan.length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
      maskByte: MASK,
    })
    issues.push('csta-xxe-forbidden')
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
    issues.push('csta-xml-incomplete', ...parsed.issues)
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
      canonicalText: spanText(text, rel),
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

  const walk = (node: XmlNode, inheritedSecret: boolean, parentLocal: string | null): void => {
    if (node.kind === 'comment' || node.kind === 'pi' || node.kind === 'doctype') return

    if (node.kind === 'text' || node.kind === 'cdata') {
      const content: XmlSpan = node.kind === 'cdata' ? node.content : node.span
      if (isWhitespaceSpan(text, content)) return
      if (inheritedSecret) {
        emitRedact(content)
        return
      }
      if (parentLocal && (SECRET_ELEMENTS.test(parentLocal) || LOCATION_ELEMENTS.test(parentLocal))) {
        emitRedact(content)
        return
      }
      if (parentLocal) {
        const baseCat = MAP_ELEMENTS.get(parentLocal)
        if (baseCat) {
          const value = spanText(text, content)
          const { category, canonical } = categorizeCstaValue(
            parentLocal,
            value,
            baseCat,
            pbxScope,
            invokeGen,
          )
          emitMap(content, category, canonical)
          return
        }
        if (STRUCTURAL_ELEMENTS.test(parentLocal)) return
      }
      // Unknown content — default mask (both levels)
      emitRedact(content)
      return
    }

    // element
    const el = node as XmlElement
    const secretHere =
      inheritedSecret
      || SECRET_ELEMENTS.test(el.localName)
      || LOCATION_ELEMENTS.test(el.localName)

    for (const attr of el.attrs) {
      if (isXmlnsAttr(attr.localName, attr.rawName)) continue
      // Non-xmlns attributes always masked (secret parents use same action)
      emitRedact(attr.value)
    }

    for (const child of el.children) {
      walk(child, secretHere, el.localName)
    }
  }

  for (const root of parsed.roots) {
    walk(root, false, null)
  }

  issues.push('csta-xml-planned')
  return { operations: ops, issues }
}

function categorizeCstaValue(
  local: string,
  value: string,
  fallback: string,
  pbxScope: string,
  invokeGen: string,
): { category: string; canonical: string } {
  const v = value.trim()
  // Keep call/monitor IDs in distinct namespaces (never merge with SIP Call-ID / other PBX).
  if (local === 'callid' || local === 'connectionid') {
    return { category: 'opaque-id', canonical: `csta-call:${pbxScope}:${v}` }
  }
  if (local === 'monitorcrossrefid') {
    return { category: 'opaque-id', canonical: `csta-monitor:${pbxScope}:${v}` }
  }
  if (local === 'invokeid') {
    return { category: 'opaque-id', canonical: `csta-invoke:${pbxScope}:${invokeGen}:${v}` }
  }
  if (/^tel:/i.test(v) || /^\+?\d{6,}$/.test(v)) {
    return { category: 'sip-phone', canonical: v }
  }
  if (/^sip:/i.test(v)) {
    return { category: 'user-id', canonical: v }
  }
  if (/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v)) {
    return { category: 'hostname', canonical: v }
  }
  if (fallback === 'person' || fallback === 'user-id') {
    return { category: fallback, canonical: v }
  }
  return { category: 'opaque-id', canonical: `csta-dev:${v}` }
}
