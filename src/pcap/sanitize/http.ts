/**
 * HTTP/1.x sanitizer (enterprise step 2 / T14).
 *
 * Headers: Host mapped; Cookie/Authorization/Set-Cookie masked as SECRET;
 * Date/Last-Modified shifted with capture TimestampMapping (or masked if unwritable).
 * Body: fail-closed — structured JSON sanitize only when exact wire length can be
 * preserved; otherwise same-length MASK (UNKNOWN_UNVERIFIED). Never leave body as
 * passthrough. Compressed / chunked bodies are always MASK (no decompress/re-encode).
 */

import type { PatchCollector } from './PatchCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { AppLayerResult } from './types'
import { patchFixedLengthAscii, computeFixedLengthAsciiBytes } from './textPatch'
import type { IntentCollector } from '../discovery/intentCollector'
import { canonicalizePcapIdentity } from '../../mapping/pcapCanonical'
import type { IdentityCategory } from '../../mapping/identityCategories'
import type { SensitiveField } from '../trust'
import {
  collectHttpBodyHeaders,
  parseHttpHeaderNameValue,
  sanitizeHttpBody,
} from './httpBody'
import { webSocketAcceptFromKey } from '../../crypto/sha1'
import { sanitizeWebSocket, looksLikeWebSocketFrame, type WebSocketSubprotocol } from './websocket'
import { deferredTextMapMeta } from './deferredMapMeta.ts'
import type { MediaFlowIndex } from '../discovery/mediaFlowIndex'

const HTTP_METHODS = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'CONNECT ', 'TRACE ']
const HEADER_SEARCH_LIMIT = 8192
const REDACT_FILLER = 0x2a // '*'

export interface HttpSanitizeResult extends AppLayerResult {
  readonly fields: readonly SensitiveField[]
}

export function sanitizeHttp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
  highPrivacy = false,
  extras?: {
    readonly mediaFlowIndex?: MediaFlowIndex
  },
): HttpSanitizeResult | null {
  const searchLen = Math.min(length, HEADER_SEARCH_LIMIT)
  const text = new TextDecoder('ascii', { fatal: false }).decode(buffer.slice(offset, offset + searchLen))

  if (!looksLikeHttp(text)) return null

  const headerEndIdx = text.indexOf('\r\n\r\n')
  if (headerEndIdx < 0) {
    return {
      coverage: [{ protocol: 'http', offset, length, status: 'requires-reassembly' }],
      fields: [{
        type: 'HTTP_MESSAGE',
        start: offset,
        length,
        classification: 'UNKNOWN_UNVERIFIED',
      }],
    }
  }

  const headerBlockLen = headerEndIdx + 4
  const lines = text.slice(0, headerEndIdx).split('\r\n')
  const fields: SensitiveField[] = []
  const startLine = lines[0] ?? ''
  const request = /^([A-Z]+ )([^ ]+)( HTTP\/1\.[01])$/.exec(startLine)
  if (request && request[2] !== '*' && request[2] !== '/') {
    const targetOffset = offset + request[1]!.length
    const target = request[2]!
    // URI path/query/userinfo may carry arbitrary identifiers, beyond the Host header.
    const replacement = target.startsWith('/') ? '/' + 'x'.repeat(target.length - 1) : 'x'.repeat(target.length)
    patchFixedLengthAscii(collector, targetOffset, target.length, replacement)
    intents?.recordFixedRedaction(packetIndex, targetOffset, target.length)
  }
  const is101 = /^HTTP\/1\.[01] 101\b/i.test(startLine)
  let upgradeWebsocket = false
  let wsSubprotocol: WebSocketSubprotocol = 'unknown'
  let wsKey: string | null = null
  let wsKeyOffset = -1
  let wsAcceptOffset = -1
  let wsAcceptLen = 0
  let permessageDeflate = false

  let cursor = (lines[0]?.length ?? 0) + 2
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!
    const parsed = parseHttpHeaderNameValue(line)
    if (parsed) {
      if (parsed.name === 'upgrade' && /websocket/i.test(parsed.value)) upgradeWebsocket = true
      if (parsed.name === 'sec-websocket-protocol') {
        const p = parsed.value.split(',')[0]?.trim().toLowerCase() ?? ''
        if (p === 'sip' || p.includes('sip')) wsSubprotocol = 'sip'
        else if (p === 'json' || p.includes('json')) wsSubprotocol = 'json'
      }
      if (parsed.name === 'sec-websocket-extensions' && /permessage-deflate/i.test(parsed.value)) {
        permessageDeflate = true
      }
      if (parsed.name === 'sec-websocket-key') {
        wsKey = parsed.value.trim()
        const colonIdx = line.indexOf(':')
        let valueIdx = colonIdx + 1
        while (valueIdx < line.length && line[valueIdx] === ' ') valueIdx++
        wsKeyOffset = offset + cursor + valueIdx
      }
      if (parsed.name === 'sec-websocket-accept') {
        const colonIdx = line.indexOf(':')
        let valueIdx = colonIdx + 1
        while (valueIdx < line.length && line[valueIdx] === ' ') valueIdx++
        wsAcceptOffset = offset + cursor + valueIdx
        wsAcceptLen = parsed.value.trim().length
      }
    }
    patchHeaderLine(line, offset + cursor, collector, mapping, intents, packetIndex, fields)
    cursor += line.length + 2
  }

  // T36 — Sec-WebSocket-Key/Accept linkage (same message only)
  if (wsKey !== null && wsKeyOffset >= 0 && /^[A-Za-z0-9+/=]+$/.test(wsKey)) {
    const constraint = { kind: 'text-ascii' as const, byteLength: wsKey.length }
    intents?.recordEntityReplacement(
      packetIndex,
      wsKeyOffset,
      'opaque-id',
      wsKey,
      wsKey.length,
      constraint,
      wsKey,
    )
    collector.addDeferred(wsKeyOffset, wsKey.length, ({ mapping: live }) => {
      const mapped = live.aliasFor('opaque-id', wsKey!, constraint, wsKey!)
      // Keep base64 alphabet for handshake validity when length matches
      const out = mapped.length === wsKey!.length ? mapped : mapped.padEnd(wsKey!.length, 'A').slice(0, wsKey!.length)
      return computeFixedLengthAsciiBytes(wsKeyOffset, wsKey!.length, out)
    }, deferredTextMapMeta('http', packetIndex, 'opaque-id', wsKey, wsKey.length, { canonical: wsKey }))

    if (wsAcceptOffset >= 0 && wsAcceptLen > 0) {
      collector.addDeferred(wsAcceptOffset, wsAcceptLen, ({ mapping: live }) => {
        const mappedKey = live.aliasFor('opaque-id', wsKey!, constraint, wsKey!)
        const keyForAccept =
          mappedKey.length === wsKey!.length
            ? mappedKey
            : mappedKey.padEnd(wsKey!.length, 'A').slice(0, wsKey!.length)
        const accept = webSocketAcceptFromKey(keyForAccept)
        if (accept.length !== wsAcceptLen) {
          return computeFixedLengthAsciiBytes(wsAcceptOffset, wsAcceptLen, '', REDACT_FILLER)
        }
        return computeFixedLengthAsciiBytes(wsAcceptOffset, wsAcceptLen, accept)
      }, { fallbackKind: 'text-x', protocol: 'http', category: 'opaque-id', packetIndex })
    }
  } else if (wsAcceptOffset >= 0 && wsAcceptLen > 0) {
    // Accept without Key in this message — mask (no independent rewrite)
    patchFixedLengthAscii(collector, wsAcceptOffset, wsAcceptLen, '', REDACT_FILLER)
    intents?.recordFixedRedaction(packetIndex, wsAcceptOffset, wsAcceptLen)
  }

  const coverage: AppLayerResult['coverage'] = [
    { protocol: 'http-headers', offset, length: headerBlockLen, status: 'covered' },
  ]

  if (length > headerBlockLen) {
    const bodyAbsOffset = offset + headerBlockLen
    const bodyLength = length - headerBlockLen
    if ((is101 && upgradeWebsocket) || (upgradeWebsocket && looksLikeWsBody(buffer, bodyAbsOffset, bodyLength))) {
      const ws = sanitizeWebSocket(
        buffer,
        bodyAbsOffset,
        bodyLength,
        collector,
        mapping,
        intents,
        packetIndex,
        {
          subprotocol: wsSubprotocol,
          mediaFlowIndex: extras?.mediaFlowIndex,
          compressed: permessageDeflate,
          highPrivacy,
        },
      )
      if (ws) {
        coverage.push(...ws.coverage)
        return { coverage, fields }
      }
    }
    const bodyResult = sanitizeHttpBody({
      buffer,
      bodyAbsOffset,
      bodyLength,
      headers: collectHttpBodyHeaders(lines),
      collector,
      mapping,
      intents,
      packetIndex,
      highPrivacy,
    })
    fields.push(...bodyResult.fields)
    if (bodyResult.childCoverage && bodyResult.childCoverage.length > 0) {
      coverage.push(...bodyResult.childCoverage)
    } else {
      coverage.push({
        protocol: 'http-body',
        offset: bodyAbsOffset,
        length: bodyLength,
        status: bodyResult.coverageStatus,
      })
    }
  }

  return { coverage, fields }
}

function looksLikeWsBody(buffer: Uint8Array, offset: number, length: number): boolean {
  return looksLikeWebSocketFrame(buffer, offset, length)
}

function looksLikeHttp(text: string): boolean {
  if (text.startsWith('HTTP/1.')) return true
  return HTTP_METHODS.some((m) => text.startsWith(m))
}

/** True when buffer starts with an HTTP/1.x request or response line. */
export function looksLikeHttpBuffer(data: Uint8Array, offset = 0, length = data.length - offset): boolean {
  const n = Math.min(length, 16)
  if (n <= 0) return false
  const text = new TextDecoder('ascii', { fatal: false }).decode(data.subarray(offset, offset + n))
  return looksLikeHttp(text)
}

function patchHeaderLine(
  line: string,
  lineStart: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  fields: SensitiveField[],
): void {
  const parsed = parseHttpHeaderNameValue(line)
  if (!parsed) return
  const { name, value } = parsed
  if (value.length === 0) return

  const colonIdx = line.indexOf(':')
  let valueIdx = colonIdx + 1
  while (valueIdx < line.length && line[valueIdx] === ' ') valueIdx++
  const valueOffset = lineStart + valueIdx

  if (name === 'host') {
    fields.push({
      type: 'HTTP_HOST',
      start: valueOffset,
      length: value.length,
      classification: 'IDENTITY',
    })
    patchHttpHost(value, valueOffset, collector, mapping, intents, packetIndex)
  } else if (
    name === 'cookie'
    || name === 'authorization'
    || name === 'set-cookie'
    || name === 'proxy-authorization'
    || name === 'referer'
    || name === 'user-agent'
    || /(?:^|-)(?:token|secret|api[_-]?key|password|passwd|auth)$/i.test(name)
    || /^x-(?:private|auth|api|session|token)/i.test(name)
  ) {
    fields.push({
      type: `HTTP_${name.toUpperCase().replace(/-/g, '_')}`,
      start: valueOffset,
      length: value.length,
      classification: 'SECRET',
    })
    patchFixedLengthAscii(collector, valueOffset, value.length, '', REDACT_FILLER)
    intents?.recordFixedRedaction(packetIndex, valueOffset, value.length)
  } else if (name === 'date' || name === 'last-modified') {
    fields.push({
      type: name === 'date' ? 'HTTP_DATE' : 'HTTP_LAST_MODIFIED',
      start: valueOffset,
      length: value.length,
      classification: 'IDENTITY',
    })
    patchHttpAbsoluteDate(value, valueOffset, collector, intents, packetIndex)
  }
}

/** T14 — capture-aligned absolute HTTP-date; mask when unparseable / unbound / length mismatch. */
function patchHttpAbsoluteDate(
  value: string,
  valueOffset: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const original = value
  collector.addDeferred(
    valueOffset,
    original.length,
    (ctx) => {
      const session = ctx.payloadTime
      if (!session) {
        return computeFixedLengthAsciiBytes(valueOffset, original.length, '', REDACT_FILLER)
      }
      const rewrite = session.rewriteHttpDateFixedLength(original)
      if (rewrite.kind === 'mask') {
        return computeFixedLengthAsciiBytes(valueOffset, original.length, '', REDACT_FILLER)
      }
      return computeFixedLengthAsciiBytes(valueOffset, original.length, rewrite.text)
    },
    { fallbackKind: 'text-x', protocol: 'http', category: 'timestamp', packetIndex },
  )
  intents?.recordFixedRedaction(packetIndex, valueOffset, original.length)
}

/** Host / Host:port / [IPv6] / [IPv6]:port — map only the identity span. */
export function splitHttpHostHeader(value: string): {
  readonly host: string
  readonly hostOffset: number
  readonly hostLength: number
} {
  if (value.startsWith('[')) {
    const close = value.indexOf(']')
    if (close > 1) {
      return { host: value.slice(1, close), hostOffset: 1, hostLength: close - 1 }
    }
  }
  const colons = (value.match(/:/g) ?? []).length
  if (colons > 1) {
    return { host: value, hostOffset: 0, hostLength: value.length }
  }
  const colon = value.lastIndexOf(':')
  if (colon > 0 && /^\d+$/.test(value.slice(colon + 1))) {
    return { host: value.slice(0, colon), hostOffset: 0, hostLength: colon }
  }
  return { host: value, hostOffset: 0, hostLength: value.length }
}

function classifyHttpHost(host: string): IdentityCategory | null {
  if (canonicalizePcapIdentity('ipv4', host)) return 'ipv4'
  if (canonicalizePcapIdentity('ipv6', host)) return 'ipv6'
  if (canonicalizePcapIdentity('hostname', host)) return 'hostname'
  return null
}

function patchHttpHost(
  value: string,
  valueOffset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const split = splitHttpHostHeader(value)
  const category = classifyHttpHost(split.host)
  if (category === null || split.hostLength <= 0) return
  const constraint = { kind: 'text-ascii' as const, byteLength: split.hostLength }
  intents?.recordEntityReplacement(
    packetIndex,
    valueOffset + split.hostOffset,
    category,
    split.host,
    split.hostLength,
    constraint,
    split.host,
  )
  collector.addDeferred(valueOffset + split.hostOffset, split.hostLength, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.aliasFor(category, split.host, constraint, split.host)
    return computeFixedLengthAsciiBytes(valueOffset + split.hostOffset, split.hostLength, mapped)
  }, deferredTextMapMeta('http', packetIndex, category, split.host, split.hostLength, { canonical: split.host }))
}
