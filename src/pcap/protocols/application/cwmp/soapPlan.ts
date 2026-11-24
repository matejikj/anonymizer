/**
 * T55 — CWMP (TR-069 / CWMP1.4) SOAP XML planner.
 * Bounded XML model; CDATA values; unknown elements/attrs fail-closed mask.
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

export interface CwmpBodySpan {
  readonly offset: number
  readonly length: number
}

export interface CwmpBodyOperation {
  readonly span: CwmpBodySpan
  readonly action: 'map' | 'redact' | 'preserve'
  readonly mappingCategory: string | null
  readonly canonicalText: string
}

const CWMP_HINT =
  /(?:urn:dslforum-org:cwmp|cwmp:|InternetGatewayDevice\.|Device\.ManagementServer|<Inform\b|<GetParameterValues\b|<SetParameterValues\b|<TransferComplete\b|<Download\b|<Upload\b)/i

const MAP_ELEMENTS: ReadonlyMap<string, string> = new Map([
  ['id', 'opaque-id'],
  ['commandkey', 'opaque-id'],
  ['serialnumber', 'opaque-id'],
  ['oui', 'opaque-id'],
  ['productclass', 'opaque-id'],
  ['manufacturer', 'opaque-id'],
  ['provisioningcode', 'opaque-id'],
  ['parameterkey', 'opaque-id'],
  ['instanceid', 'opaque-id'],
  ['objectname', 'opaque-id'],
])

const SECRET_ELEMENTS =
  /^(?:password|username|passphrase|psk|sharedsecret|connectionrequestpassword|connectionrequestusername|authpassword|authusername|nonce|realm|certificate|privatekey|key)$/i

const URL_ELEMENTS = /^(?:url|downloadurl|uploadurl|connectionrequesturl|nextlevelurl|acsurl)$/i

const SECRET_PARAM_NAME =
  /(?:password|passphrase|psk|secret|key|token|credential|auth|wifi\.|wlan\.|sip\.|certificate)/i

const IDENTITY_PARAM_NAME =
  /(?:\.(?:macaddress|ipaddress|externalipaddress|hostname|username|serialnumber|imei|imsi|phone|number)|managementserver\.url)/i

const PRESERVE_PARAM_NAME =
  /(?:\.(?:enablenat|enable|status|uptime|errorcode|maxenvelopes|retrycount|periodicinforminterval)$|device\.deviceinfo\.(?:modelname|softwareversion|hardwareversion))/i

const FAULT_ELEMENTS = /^(?:faultstring|errormessage|faultdetail)$/i

/** SOAP/CWMP wrappers that carry no direct semantic text. */
const STRUCTURAL_ELEMENTS =
  /^(?:envelope|header|body|inform|informresponse|getparametervalues|getparametervaluesresponse|setparametervalues|setparametervaluesresponse|getparameternames|getparameterattributes|setparameterattributes|addobject|deleteobject|download|upload|transfercomplete|reboot|factoryreset|parameterlist|parameternames|parameterattributes|deviceid|event|eventstruct|fault|detail|parametervaluestruct)$/i

export function looksLikeCwmpSoapText(text: string): boolean {
  if (text.length < 24) return false
  return CWMP_HINT.test(text) || /<(?:[\w.-]+:)?(?:Envelope|Inform|GetParameterValues)\b/i.test(text)
}

export function looksLikeCwmpContentType(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.trim().split(';')[0]?.trim().toLowerCase() ?? ''
  return (
    base === 'text/xml'
    || base === 'application/xml'
    || base === 'application/soap+xml'
    || base.includes('soap')
  )
}

/**
 * Plan map/redact ops for a CWMP SOAP body (absolute offsets into `buffer`).
 */
export function buildCwmpSoapBodyPlan(
  buffer: Uint8Array,
  bodySpan: CwmpBodySpan,
): { readonly operations: readonly CwmpBodyOperation[]; readonly issues: readonly string[] } {
  const ops: CwmpBodyOperation[] = []
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
    })
    issues.push('cwmp-xxe-forbidden')
    return { operations: ops, issues }
  }

  if (!looksLikeCwmpSoapText(text)) {
    return { operations: ops, issues: ['cwmp-not-matched'] }
  }

  const parsed = parseBoundedXml(text)
  if (!parsed.complete) {
    ops.push({
      span: { offset: bodySpan.offset, length: bodySpan.length },
      action: 'redact',
      mappingCategory: null,
      canonicalText: '',
    })
    issues.push('cwmp-xml-incomplete', ...parsed.issues)
    return { operations: ops, issues }
  }

  const seen = new Set<string>()
  const emit = (
    rel: XmlSpan,
    action: 'map' | 'redact',
    mappingCategory: string | null,
    canonicalText: string,
  ): void => {
    const length = rel.end - rel.start
    if (length <= 0) return
    const key = `${rel.start}:${rel.end}`
    if (seen.has(key)) return
    seen.add(key)
    ops.push({
      span: { offset: bodySpan.offset + rel.start, length },
      action,
      mappingCategory,
      canonicalText,
    })
  }

  const emitRedact = (rel: XmlSpan): void => {
    emit(rel, 'redact', null, spanText(text, rel))
  }

  const collectContentSpans = (el: XmlElement): XmlSpan[] => {
    const out: XmlSpan[] = []
    for (const child of el.children) {
      if (child.kind === 'text') {
        if (!isWhitespaceSpan(text, child.span)) out.push(child.span)
      } else if (child.kind === 'cdata') {
        if (!isWhitespaceSpan(text, child.content)) out.push(child.content)
      } else if (child.kind === 'element') {
        // Nested typed value wrappers — recurse content
        out.push(...collectContentSpans(child))
      }
    }
    return out
  }

  const directChild = (el: XmlElement, local: string): XmlElement | null => {
    for (const child of el.children) {
      if (child.kind === 'element' && child.localName === local) return child
    }
    return null
  }

  const applyValueDisposition = (valueEl: XmlElement, name: string): void => {
    const nameLower = name.toLowerCase()
    const spans = collectContentSpans(valueEl)
    for (const attr of valueEl.attrs) {
      if (isXmlnsAttr(attr.localName, attr.rawName)) continue
      // type/arrayType attrs are structural — preserve short schema tokens only
      if (
        (attr.localName === 'type' || attr.localName === 'arraytype')
        && /^[\w.:-]+$/.test(spanText(text, attr.value))
      ) {
        continue
      }
      emitRedact(attr.value)
    }

    if (SECRET_PARAM_NAME.test(nameLower) || SECRET_ELEMENTS.test(leaf(nameLower))) {
      for (const s of spans) emitRedact(s)
      return
    }
    if (spans.length === 1) {
      const value = spanText(text, spans[0]!)
      if (PRESERVE_PARAM_NAME.test(nameLower) && /^(?:true|false|\d+)$/i.test(value.trim())) {
        return
      }
      if (IDENTITY_PARAM_NAME.test(nameLower) || URL_ELEMENTS.test(leaf(nameLower))) {
        const cat = classifyIdentityValue(value)
        emit(spans[0]!, 'map', cat.category, cat.canonical)
        return
      }
    }
    for (const s of spans) emitRedact(s)
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
      if (parentLocal && SECRET_ELEMENTS.test(parentLocal)) {
        emitRedact(content)
        return
      }
      if (parentLocal && FAULT_ELEMENTS.test(parentLocal)) {
        emitRedact(content)
        return
      }
      if (parentLocal && URL_ELEMENTS.test(parentLocal)) {
        const value = spanText(text, content)
        emit(content, 'map', 'opaque-id', `cwmp-url:${value}`)
        return
      }
      if (parentLocal) {
        const baseCat = MAP_ELEMENTS.get(parentLocal)
        if (baseCat) {
          const value = spanText(text, content)
          emit(content, 'map', baseCat, `cwmp-${parentLocal}:${value}`)
          return
        }
        // Schema-shaped parameter paths stay readable; custom labels map
        if (parentLocal === 'name') {
          const value = spanText(text, content)
          if (/^(?:Device|InternetGatewayDevice)(?:\.[A-Za-z][\w]*)+$/i.test(value)) return
          if (SECRET_PARAM_NAME.test(value) || /[^A-Za-z0-9._-]/.test(value)) {
            emit(content, 'map', 'opaque-id', `cwmp-path:${value}`)
            return
          }
          return
        }
        if (STRUCTURAL_ELEMENTS.test(parentLocal)) return
      }
      emitRedact(content)
      return
    }

    const el = node as XmlElement
    const secretHere = inheritedSecret || SECRET_ELEMENTS.test(el.localName)

    // ParameterValueStruct: Name decides Value disposition (text + CDATA)
    if (el.localName === 'parametervaluestruct') {
      for (const attr of el.attrs) {
        if (!isXmlnsAttr(attr.localName, attr.rawName)) emitRedact(attr.value)
      }
      const nameEl = directChild(el, 'name')
      const valueEl = directChild(el, 'value')
      if (nameEl) {
        for (const attr of nameEl.attrs) {
          if (!isXmlnsAttr(attr.localName, attr.rawName)) emitRedact(attr.value)
        }
        const nameSpans = collectContentSpans(nameEl)
        const nameText = nameSpans.map((s) => spanText(text, s)).join('')
        if (nameText && !/^(?:Device|InternetGatewayDevice)(?:\.[A-Za-z][\w]*)+$/i.test(nameText)) {
          if (SECRET_PARAM_NAME.test(nameText) || /[^A-Za-z0-9._-]/.test(nameText)) {
            for (const s of nameSpans) {
              emit(s, 'map', 'opaque-id', `cwmp-path:${spanText(text, s)}`)
            }
          }
        }
        if (valueEl) applyValueDisposition(valueEl, nameText)
        else {
          // Missing Value — still walk other children as unknown
          for (const child of el.children) {
            if (child !== nameEl) walk(child, true, el.localName)
          }
        }
        // Walk non Name/Value siblings as unknown/secret
        for (const child of el.children) {
          if (child === nameEl || child === valueEl) continue
          walk(child, true, el.localName)
        }
        return
      }
      // No Name — fail-closed on whole struct content
      for (const child of el.children) walk(child, true, el.localName)
      return
    }

    for (const attr of el.attrs) {
      if (isXmlnsAttr(attr.localName, attr.rawName)) continue
      if (
        (attr.localName === 'mustunderstand' || attr.localName === 'arraytype' || attr.localName === 'type')
        && /^[\w.:[\]]+$/.test(spanText(text, attr.value))
      ) {
        continue
      }
      emitRedact(attr.value)
    }

    for (const child of el.children) {
      walk(child, secretHere, el.localName)
    }
  }

  for (const root of parsed.roots) {
    walk(root, false, null)
  }

  issues.push('cwmp-soap-planned')
  return { operations: ops, issues }
}

function leaf(raw: string): string {
  const s = raw.includes(':') ? raw.slice(raw.indexOf(':') + 1) : raw
  return s.toLowerCase()
}

function classifyIdentityValue(value: string): { category: string; canonical: string } {
  const v = value.trim()
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) {
    return { category: 'ipv4', canonical: v }
  }
  if (/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i.test(v)) {
    return { category: 'mac', canonical: v.toLowerCase() }
  }
  if (/^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v)) {
    return { category: 'hostname', canonical: v.toLowerCase() }
  }
  if (/^https?:\/\//i.test(v)) {
    return { category: 'opaque-id', canonical: `cwmp-url:${v}` }
  }
  return { category: 'opaque-id', canonical: `cwmp-val:${v}` }
}
