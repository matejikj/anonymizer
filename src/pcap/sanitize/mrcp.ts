/**
 * T54 — MRCPv2 (RFC 6787): control-channel speech resources.
 * Preserve method/status/request-state/completion-cause; map Channel-Identifier;
 * always mask transcript/grammar/SSML/NLSML/voiceprint and recording URIs.
 */

import type { PatchCollector } from './PatchCollector.ts'
import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from './maskFill.ts'
import { computeFixedLengthAsciiBytes } from './textPatch.ts'
import { maskPayloadSpan } from '../protocols/application/textproto'
import {
  isWhitespaceSpan,
  isXmlnsAttr,
  parseBoundedXml,
  spanText,
  type XmlElement,
  type XmlNode,
  type XmlSpan,
} from './mrcpBoundedXml.ts'

/** Occasional fixed control ports; content probe (`MRCP/2.0`) is authoritative. */
export const MRCP_TCP_PORTS = new Set([3242])

const KNOWN_RESOURCES = new Set([
  'speechrecog',
  'speechsynth',
  'recorder',
  'speakverify',
  'speechverify',
  'telephony',
])

const PRESERVE_HEADERS = new Set([
  'content-length',
  'content-type',
  'content-encoding',
  'completion-cause',
  'completion-reason', // code prefix preserved; free text masked separately
  'request-state',
  'proxy-sync-id',
  'fetch-timeout',
  'recognition-timeout',
  'speech-complete-timeout',
  'speech-incomplete-timeout',
  'no-input-timeout',
  'confidence-threshold',
  'sensitivity-level',
  'speed-vs-accuracy',
  'n-best-list-length',
  'start-input-timers',
  'failed-uri-cause',
  'abort',
  'kill-on-barge-in',
  'barge-in',
  'voice-gender',
  'voice-age',
  'prosody-volume',
  'prosody-rate',
  'audio-fetch-hint',
  'media-type',
])

const MAP_CHANNEL = 'channel-identifier'
const MAP_CONTENT_ID = 'content-id'
const MAP_ACTIVE_LIST = 'active-request-id-list'

const MASK_HEADERS = new Set([
  'interpret-text',
  'waveform-uri',
  'media-url',
  'media-uri',
  'logging-tag',
  'vendor-specific',
  'vendor-specific-parameters',
  'voice-name',
  'speaker-profile',
  'voiceprint',
  'voiceprint-identifier',
  'voiceprint-uri',
  'repository-uri',
  'verification-mode',
  'adapt-model',
  'enroll-utterance',
  'phrase-id',
  'phrase-nl',
  'input-waveform-uri',
  'failed-uri',
  'proxy-get-uri',
  'speech-marker',
  'set-cookie',
  'set-cookie2',
  'cookie',
  'authentication-info',
  'proxy-authentication-info',
])

const CONTENT_MASK_TYPES =
  /(?:nlsml|ssml|srgs|grammar|abnf|xml|plain|uri-list|octet-stream|wav|audio)/i

export function isMrcpPortHint(src: number, dst: number): boolean {
  return MRCP_TCP_PORTS.has(src) || MRCP_TCP_PORTS.has(dst)
}

export function looksLikeMrcp(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 12) return false
  const head = decodeAscii(buffer, offset, Math.min(length, 48))
  return /^MRCP\/2\.0\s+\d+/i.test(head)
}

export function sanitizeMrcp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeMrcp(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset
  let n = 0

  while (pos + 12 <= end && n < 16) {
    n++
    if (!looksLikeMrcp(buffer, pos, end - pos)) {
      maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, 'mrcp-trailer')
      coverage.push({
        protocol: 'mrcp-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      break
    }
    const msg = sanitizeOneMessage(
      buffer,
      pos,
      end - pos,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
    )
    if (msg <= 0) break
    pos += msg
  }

  if (coverage.length === 0) return null
  coverage.unshift({ protocol: 'mrcp', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeOneMessage(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): number {
  const text = decodeAscii(buffer, offset, Math.min(length, 8192))
  const lineEnd = text.indexOf('\r\n')
  if (lineEnd < 0) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'mrcp-start-trunc')
    coverage.push({ protocol: 'mrcp', offset, length, status: 'requires-reassembly' })
    issues.push('mrcp-start-line-incomplete')
    return length
  }

  const startLine = text.slice(0, lineEnd)
  const m = /^MRCP\/2\.0\s+(\d+)\s+(.+)$/i.exec(startLine)
  if (!m) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'mrcp-start-bad')
    coverage.push({ protocol: 'mrcp', offset, length, status: 'malformed' })
    issues.push('mrcp-start-line-bad')
    return length
  }

  const messageLength = Number.parseInt(m[1]!, 10)
  if (!Number.isFinite(messageLength) || messageLength < startLine.length + 2 || messageLength > 1_048_576) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'mrcp-bad-len')
    coverage.push({ protocol: 'mrcp', offset, length, status: 'malformed' })
    issues.push('mrcp-bad-message-length')
    return length
  }

  if (messageLength > length) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'mrcp-partial')
    coverage.push({
      protocol: 'mrcp',
      offset,
      length,
      status: 'requires-reassembly',
    })
    issues.push('mrcp-requires-reassembly')
    return length
  }

  coverage.push({
    protocol: 'mrcp-hdr',
    offset,
    length: lineEnd + 2,
    status: 'covered',
  })

  // Headers
  const headerBlockStart = lineEnd + 2
  const headerSearch = text.slice(headerBlockStart)
  const headerEndRel = headerSearch.indexOf('\r\n\r\n')
  if (headerEndRel < 0) {
    maskPayloadSpan(
      collector,
      offset + headerBlockStart,
      messageLength - headerBlockStart,
      intents,
      packetIndex,
      'mrcp-headers-trunc',
    )
    coverage.push({
      protocol: 'mrcp',
      offset,
      length: messageLength,
      status: 'requires-reassembly',
    })
    issues.push('mrcp-headers-incomplete')
    return messageLength
  }

  const headerBlockLen = headerEndRel + 4
  const headerText = headerSearch.slice(0, headerEndRel)
  let contentType: string | null = null
  let contentLength: number | null = null
  let cursor = 0
  for (const rawLine of headerText.split('\r\n')) {
    const absLine = offset + headerBlockStart + cursor
    const colon = rawLine.indexOf(':')
    if (colon > 0) {
      const name = rawLine.slice(0, colon).trim().toLowerCase()
      let valueStart = colon + 1
      if (rawLine[valueStart] === ' ') valueStart++
      const value = rawLine.slice(valueStart)
      const valueAbs = absLine + valueStart
      const valueLen = value.length

      if (name === 'content-type') contentType = value
      if (name === 'content-length') {
        const n = Number.parseInt(value.trim(), 10)
        if (Number.isFinite(n)) contentLength = n
      }

      sanitizeHeader(
        name,
        value,
        valueAbs,
        valueLen,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    }
    cursor += rawLine.length + 2
  }

  coverage.push({
    protocol: 'mrcp-hdr',
    offset: offset + headerBlockStart,
    length: headerBlockLen,
    status: 'covered',
  })

  const bodyOff = offset + headerBlockStart + headerBlockLen
  const bodyAvail = offset + messageLength - bodyOff
  const bodyLen = contentLength !== null ? Math.min(contentLength, bodyAvail) : bodyAvail

  if (bodyLen > 0) {
    sanitizeBody(
      buffer,
      bodyOff,
      bodyLen,
      contentType,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
    )
  }

  // Trailing padding inside message-length after body
  const afterBody = bodyOff + bodyLen
  const msgEnd = offset + messageLength
  if (afterBody < msgEnd) {
    coverage.push({
      protocol: 'mrcp',
      offset: afterBody,
      length: msgEnd - afterBody,
      status: 'covered',
    })
  }

  return messageLength
}

function sanitizeHeader(
  name: string,
  value: string,
  valueAbs: number,
  valueLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (valueLen <= 0) return

  if (name === MAP_CHANNEL) {
    sanitizeChannelIdentifier(
      value,
      valueAbs,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
    )
    return
  }

  if (name === MAP_CONTENT_ID || name === 'content-location') {
    mapAscii(
      valueAbs,
      valueLen,
      value,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'mrcp-cid:',
    )
    coverage.push({ protocol: 'mrcp-id', offset: valueAbs, length: valueLen, status: 'covered' })
    return
  }

  if (name === MAP_ACTIVE_LIST) {
    // Numeric list — preserve (correlation)
    coverage.push({ protocol: 'mrcp', offset: valueAbs, length: valueLen, status: 'covered' })
    return
  }

  if (name === 'completion-reason') {
    // "000 normal" — preserve code, mask free text after first token
    const sp = value.search(/\s/)
    if (sp > 0 && sp + 1 < valueLen) {
      maskPayloadSpan(
        collector,
        valueAbs + sp + 1,
        valueLen - sp - 1,
        intents,
        packetIndex,
        'mrcp-reason',
      )
      coverage.push({
        protocol: 'mrcp-body',
        offset: valueAbs + sp + 1,
        length: valueLen - sp - 1,
        status: 'redacted',
      })
    }
    coverage.push({ protocol: 'mrcp', offset: valueAbs, length: Math.max(sp, 0), status: 'covered' })
    return
  }

  if (PRESERVE_HEADERS.has(name)) {
    coverage.push({ protocol: 'mrcp', offset: valueAbs, length: valueLen, status: 'covered' })
    return
  }

  if (
    MASK_HEADERS.has(name)
    || name.includes('uri')
    || name.includes('url')
    || name.includes('voiceprint')
    || name.includes('grammar')
  ) {
    maskPayloadSpan(collector, valueAbs, valueLen, intents, packetIndex, `mrcp-${name}`)
    coverage.push({
      protocol: name.includes('voiceprint') ? 'mrcp-auth' : 'mrcp-body',
      offset: valueAbs,
      length: valueLen,
      status: 'redacted',
    })
    if (name.includes('voiceprint')) issues.push('mrcp-voiceprint-masked')
    return
  }

  // Unknown header — fail-closed mask
  maskPayloadSpan(collector, valueAbs, valueLen, intents, packetIndex, `mrcp-hdr-${name}`)
  coverage.push({
    protocol: 'mrcp-body',
    offset: valueAbs,
    length: valueLen,
    status: 'redacted',
  })
}

function sanitizeChannelIdentifier(
  value: string,
  valueAbs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  const at = value.indexOf('@')
  if (at <= 0) {
    mapAscii(
      valueAbs,
      value.length,
      value,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'mrcp-ch:',
    )
    coverage.push({ protocol: 'mrcp-id', offset: valueAbs, length: value.length, status: 'covered' })
    return
  }
  const session = value.slice(0, at)
  const resource = value.slice(at + 1).toLowerCase()
  mapAscii(
    valueAbs,
    session.length,
    session,
    'opaque-id',
    collector,
    mapping,
    intents,
    packetIndex,
    'mrcp-ch:',
  )
  coverage.push({
    protocol: 'mrcp-id',
    offset: valueAbs,
    length: session.length,
    status: 'covered',
  })
  // '@resource' — preserve known resource enum; mask unknown
  const resAbs = valueAbs + at
  if (KNOWN_RESOURCES.has(resource)) {
    coverage.push({
      protocol: 'mrcp',
      offset: resAbs,
      length: value.length - at,
      status: 'covered',
    })
  } else {
    maskPayloadSpan(
      collector,
      resAbs + 1,
      value.length - at - 1,
      intents,
      packetIndex,
      'mrcp-resource',
    )
    coverage.push({
      protocol: 'mrcp-body',
      offset: resAbs + 1,
      length: value.length - at - 1,
      status: 'redacted',
    })
  }
}

function sanitizeBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
  contentType: string | null,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const ct = contentType?.toLowerCase() ?? ''
  if (CONTENT_MASK_TYPES.test(ct) || ct.includes('xml') || ct.includes('grammar')) {
    const text = decodeAscii(buffer, offset, length)
    if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) {
      maskPayloadSpan(collector, offset, length, intents, packetIndex, 'mrcp-xxe')
      coverage.push({ protocol: 'mrcp-body', offset, length, status: 'malformed' })
      issues.push('mrcp-xxe-forbidden')
      return
    }
    if (/<[A-Za-z]/.test(text)) {
      const planned = planSpeechXmlOps(text, offset)
      if (!planned.complete) {
        // Unproven speech body — mask entire unit (never partial green)
        maskPayloadSpan(collector, offset, length, intents, packetIndex, 'mrcp-xml-incomplete')
        coverage.push({ protocol: 'mrcp-body', offset, length, status: 'redacted' })
        issues.push('mrcp-body-masked', ...planned.issues)
        return
      }
      for (const op of planned.ops) {
        if (op.action === 'mask') {
          maskPayloadSpan(collector, op.offset, op.length, intents, packetIndex, 'mrcp-xml')
          coverage.push({
            protocol: 'mrcp-body',
            offset: op.offset,
            length: op.length,
            status: 'redacted',
          })
        } else {
          mapAscii(
            op.offset,
            op.length,
            op.text,
            'opaque-id',
            collector,
            mapping,
            intents,
            packetIndex,
            'mrcp-xml:',
          )
          coverage.push({
            protocol: 'mrcp-id',
            offset: op.offset,
            length: op.length,
            status: 'covered',
          })
        }
      }
      coverage.push({ protocol: 'mrcp-body', offset, length, status: 'covered' })
      issues.push('mrcp-speech-content-masked')
      return
    }
  }

  // Default: entire body is speech/content — always mask both levels
  maskPayloadSpan(collector, offset, length, intents, packetIndex, 'mrcp-body')
  coverage.push({ protocol: 'mrcp-body', offset, length, status: 'redacted' })
  issues.push('mrcp-body-masked')
  void mapping
}

type SpeechXmlOp = { action: 'mask' | 'map'; offset: number; length: number; text: string }

function planSpeechXmlOps(
  text: string,
  baseOffset: number,
): { ops: SpeechXmlOp[]; complete: boolean; issues: string[] } {
  const parsed = parseBoundedXml(text)
  if (!parsed.complete) {
    return { ops: [], complete: false, issues: [...parsed.issues, 'mrcp-xml-incomplete'] }
  }

  const ops: SpeechXmlOp[] = []
  const seen = new Set<string>()
  const emit = (rel: XmlSpan, action: 'mask' | 'map'): void => {
    const length = rel.end - rel.start
    if (length <= 0) return
    const key = `${rel.start}:${rel.end}`
    if (seen.has(key)) return
    seen.add(key)
    ops.push({
      action,
      offset: baseOffset + rel.start,
      length,
      text: spanText(text, rel),
    })
  }

  const PRESERVE_NUMERIC =
    /^(?:confidence|grammar|mode|timestamp|swirec_name|swirec_confidence)$/i
  const MAP_LOCAL = /^(?:id|grammarid|contentid)$/i

  const walk = (node: XmlNode, parentLocal: string | null): void => {
    if (node.kind === 'comment' || node.kind === 'pi' || node.kind === 'doctype') return

    if (node.kind === 'text' || node.kind === 'cdata') {
      const content: XmlSpan = node.kind === 'cdata' ? node.content : node.span
      if (isWhitespaceSpan(text, content)) return
      const value = spanText(text, content)
      if (parentLocal && PRESERVE_NUMERIC.test(parentLocal) && /^[\d.]+$/.test(value.trim())) {
        return
      }
      if (parentLocal && MAP_LOCAL.test(parentLocal)) {
        emit(content, 'map')
        return
      }
      // All speech / unknown text + CDATA — mask both levels
      emit(content, 'mask')
      return
    }

    const el = node as XmlElement
    for (const attr of el.attrs) {
      if (isXmlnsAttr(attr.localName, attr.rawName)) continue
      if (
        (attr.localName === 'mode' || attr.localName === 'confidence')
        && /^[\w.-]+$/.test(spanText(text, attr.value))
        && spanText(text, attr.value).length <= 16
      ) {
        continue
      }
      emit(attr.value, 'mask')
    }
    for (const child of el.children) {
      walk(child, el.localName)
    }
  }

  for (const root of parsed.roots) {
    walk(root, null)
  }
  return { ops, complete: true, issues: [] }
}

function mapAscii(
  offset: number,
  length: number,
  text: string,
  category: 'opaque-id',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  prefix?: string,
): void {
  void mapping
  if (length <= 0 || text.length === 0) return
  const forCanon = prefix ? `${prefix}${text}` : text
  const canon = canonicalizeIdentity(category, forCanon) ?? forCanon
  const constraint = { kind: 'text-ascii' as const, byteLength: length }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, length, constraint, text)
  try {
    collector.addDeferred(
      offset,
      length,
      ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(
            offset,
            length,
            live.aliasFor(category, canon, constraint, text),
          )
        } catch {
          return createProtocolNeutralMaskFill({
            length,
            packetIndex,
            offset,
            domain: `mrcp-${category}`,
          })
        }
      },
      { fallbackKind: 'text-x', protocol: 'mrcp', category, packetIndex },
    )
  } catch {
    /* overlap */
  }
}

function decodeAscii(buffer: Uint8Array, offset: number, length: number): string {
  return new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
}
