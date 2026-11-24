/**
 * Enterprise step 2 — HTTP body classification + fail-closed sanitization.
 *
 * Structured sanitize only when the wire representation can keep exact byte length.
 * Otherwise MASK the raw body in place (never leave-as-is, never decompress/re-encode).
 */

import type { FieldClassification, SensitiveField } from '../trust'
import type { PatchCollector } from './PatchCollector'
import type { IntentCollector } from '../discovery/intentCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { CoverageStatus } from './types'
import { patchFixedLengthAscii, computeFixedLengthAsciiBytes } from './textPatch'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizePcapIdentity } from '../../mapping/pcapCanonical'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import type { IdentityCategory } from '../../mapping/identityCategories'
import { sanitizeTextPayload } from '../protocols/application/textproto'
import { cwmpSoapEligible, sanitizeCwmpSoapBody } from './cwmp.ts'
import type { LayerCoverage } from './types'

/** Length-preserving filler inside JSON string/key wire spans (valid JSON text). */
export const JSON_LEXEME_REDACT_BYTE = 0x2a // '*'

/** Length-preserving filler for XML text, CDATA, and attribute values. */
export const XML_TEXT_REDACT_BYTE = 0x78 // 'x'

const SECRET_KEY_RE =
  /^(?:pass(?:word)?|passwd|pwd|token|secret|auth(?:orization)?|api[_-]?key|access[_-]?token|refresh[_-]?token|cookie|session(?:id)?)$/i
const PHONE_RE = /^\+?\d{9,15}$/
const EMAIL_RE = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i

export type HttpBodyDisposition =
  | 'structured-sanitized'
  | 'masked-unverified'
  | 'empty'

export interface HttpBodySanitizeResult {
  readonly disposition: HttpBodyDisposition
  readonly coverageStatus: CoverageStatus
  readonly fields: readonly SensitiveField[]
  /** Nested protocol coverage (e.g. CWMP SOAP). */
  readonly childCoverage?: readonly LayerCoverage[]
  readonly issues?: readonly string[]
}

export interface HttpBodyHeaders {
  readonly contentType: string | null
  readonly contentEncoding: string | null
  readonly transferEncoding: string | null
}

export function parseHttpHeaderNameValue(line: string): { name: string; value: string } | null {
  const colonIdx = line.indexOf(':')
  if (colonIdx < 0) return null
  const name = line.slice(0, colonIdx).trim().toLowerCase()
  let valueIdx = colonIdx + 1
  while (valueIdx < line.length && line[valueIdx] === ' ') valueIdx++
  return { name, value: line.slice(valueIdx) }
}

export function collectHttpBodyHeaders(headerLines: readonly string[]): HttpBodyHeaders {
  let contentType: string | null = null
  let contentEncoding: string | null = null
  let transferEncoding: string | null = null
  for (let i = 1; i < headerLines.length; i++) {
    const parsed = parseHttpHeaderNameValue(headerLines[i]!)
    if (!parsed) continue
    if (parsed.name === 'content-type') contentType = parsed.value.toLowerCase()
    else if (parsed.name === 'content-encoding') contentEncoding = parsed.value.toLowerCase()
    else if (parsed.name === 'transfer-encoding') transferEncoding = parsed.value.toLowerCase()
  }
  return { contentType, contentEncoding, transferEncoding }
}

function isCompressedEncoding(encoding: string | null): boolean {
  if (!encoding || encoding === 'identity') return false
  return /(?:gzip|deflate|br|compress|zstd)/i.test(encoding)
}

function isChunked(transferEncoding: string | null): boolean {
  return transferEncoding !== null && /chunked/i.test(transferEncoding)
}

function isJsonContentType(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.split(';')[0]!.trim()
  return base === 'application/json' || base.endsWith('+json')
}

function isPlainTextContentType(contentType: string | null): boolean {
  if (!contentType) return false
  const base = contentType.split(';')[0]!.trim().toLowerCase()
  return base === 'text/plain' || base === 'text/csv' || base.startsWith('text/')
}

function classifyJsonStringValue(value: string): IdentityCategory | 'secret-shaped' | null {
  if (PHONE_RE.test(value) && canonicalizeIdentity('sip-phone', value)) return 'sip-phone'
  if (canonicalizePcapIdentity('ipv4', value)) return 'ipv4'
  if (canonicalizePcapIdentity('ipv6', value)) return 'ipv6'
  // Require a real FQDN (dot + non-numeric TLD) — bare tokens like "ok" must stay.
  if (value.includes('.') && canonicalizePcapIdentity('hostname', value)) {
    const last = value.slice(value.lastIndexOf('.') + 1)
    if (!/^[0-9]+$/.test(last) && value === value.toLowerCase()) return 'hostname'
  }
  if (EMAIL_RE.test(value) && canonicalizeIdentity('email', value)) return 'email'
  if (value.length >= 8 && /^(?:Bearer\s+|Basic\s+)/i.test(value)) return 'secret-shaped'
  if (value.length >= 16 && /^[A-Za-z0-9_\-.=+/]+$/.test(value) && /[A-Za-z]/.test(value) && /\d/.test(value)) {
    return 'secret-shaped'
  }
  return null
}

export type JsonLexemeKind = 'key' | 'string' | 'number'

/**
 * One JSON semantic leaf with exact wire offsets (RFC 8259 subset, ASCII/UTF-8 1:1).
 * Array items inherit the enclosing property key (`precedingKey`).
 */
export interface JsonLexemeSpan {
  readonly kind: JsonLexemeKind
  /** Absolute offset of the lexeme content (inside quotes for strings/keys). */
  readonly absOffset: number
  readonly byteLength: number
  /** Raw wire content (escape sequences kept as written). */
  readonly raw: string
  /** JSON-decoded content for keys/strings; same as raw for numbers. */
  readonly decoded: string
  /** Decoded enclosing property key for values; null for keys and root array items. */
  readonly precedingKey: string | null
  /** Raw (undecoded) enclosing property key wire text; null when precedingKey is null. */
  readonly precedingKeyRaw: string | null
}

export interface JsonStringSpan {
  readonly absOffset: number
  readonly byteLength: number
  readonly value: string
  readonly precedingKey: string | null
}

/** Public / non-identifying keys whose non-secret values may stay in untyped JSON. */
const JSON_PUBLIC_KEY_RE =
  /^(?:status|version|level|ok|type|cause|n|count|index|line|facility|timestamp|time|ts|duration|size|length|port|code|http_?status|statusCode|success|error|msg|message|short_message|full_message|host|source|src|dst|file|method|path|proto|protocol|priority|id|5qi|qi|sst|sd)$/i

/**
 * Decode JSON string content escapes (RFC 8259) for policy / classification.
 * Unknown escapes are left best-effort; malformed sequences keep the raw remainder.
 */
export function decodeJsonStringContent(raw: string): string {
  let out = ''
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i]!
    if (c !== '\\' || i + 1 >= raw.length) {
      out += c
      continue
    }
    const n = raw[i + 1]!
    if (n === 'u' && i + 5 < raw.length) {
      const hex = raw.slice(i + 2, i + 6)
      if (/^[0-9a-fA-F]{4}$/.test(hex)) {
        out += String.fromCharCode(parseInt(hex, 16))
        i += 5
        continue
      }
    }
    const mapped =
      n === '"' || n === '\\' || n === '/'
        ? n
        : n === 'b'
          ? '\b'
          : n === 'f'
            ? '\f'
            : n === 'n'
              ? '\n'
              : n === 'r'
                ? '\r'
                : n === 't'
                  ? '\t'
                  : n
    out += mapped
    i++
  }
  return out
}

/** Grammar-valid, length-preserving numeric redaction (digit → 0). */
export function maskJsonNumberRaw(raw: string): string {
  return raw.replace(/[0-9]/g, '0')
}

export function jsonKeyHasEscape(raw: string): boolean {
  return raw.includes('\\')
}

export function isJsonPublicKey(key: string): boolean {
  return JSON_PUBLIC_KEY_RE.test(key)
}

export function isJsonSecretKey(key: string): boolean {
  return SECRET_KEY_RE.test(key)
}

/**
 * Dynamic / canary-shaped property names are themselves sensitive.
 * Ordinary camelCase/snake_case schema identifiers keep their wire spelling;
 * unknown *values* still default to mask via {@link isJsonPublicKey}.
 */
export function shouldMaskJsonKeyName(decoded: string): boolean {
  if (isJsonPublicKey(decoded) || isJsonSecretKey(decoded)) return false
  // Ordinary schema identifiers (incl. leading-digit tokens like 5qi).
  const schemaIdent = /^[A-Za-z_][A-Za-z0-9_]*$/.test(decoded) || /^[0-9][A-Za-z][A-Za-z0-9_]*$/.test(decoded)
  if (!schemaIdent) return true
  // SCREAMING_SNAKE / AUDIT_* style dynamic keys
  if (/^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$/.test(decoded)) return true
  if (decoded.length >= 20 && /[A-Z]/.test(decoded) && /\d/.test(decoded) && decoded.includes('_')) {
    return true
  }
  return false
}

/**
 * Walk JSON text and return every key / string value / number lexeme with source spans.
 * Returns null when the body is not safely walkable as length-stable JSON text.
 */
export function findJsonLexemeSpans(body: Uint8Array, bodyAbsOffset: number): JsonLexemeSpan[] | null {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(body)
  // Reject if UTF-8 decode length diverges from bytes (multi-byte) — we patch by byte length.
  if (text.length !== body.length) return null

  const spans: JsonLexemeSpan[] = []
  let i = 0
  /**
   * Container stack: object vs array, plus inherited property key for array elements
   * (and for nested arrays under that property).
   */
  const containers: Array<{ readonly isObject: boolean; readonly inheritKey: string | null; readonly inheritKeyRaw: string | null }> =
    []
  let pendingKey: string | null = null
  let pendingKeyRaw: string | null = null
  let afterColon = false

  const skipWs = () => {
    while (i < text.length && (text[i] === ' ' || text[i] === '\t' || text[i] === '\n' || text[i] === '\r')) i++
  }

  const top = () => containers[containers.length - 1]
  const inObject = () => top()?.isObject === true

  const valuePreceding = (): { key: string | null; keyRaw: string | null } => {
    if (inObject()) return { key: pendingKey, keyRaw: pendingKeyRaw }
    const t = top()
    return { key: t?.inheritKey ?? null, keyRaw: t?.inheritKeyRaw ?? null }
  }

  const readString = (): { raw: string; innerStart: number; innerLen: number } | null => {
    const start = i
    i++
    let raw = ''
    while (i < text.length) {
      const c = text[i]!
      if (c === '"') {
        i++
        const innerStart = start + 1
        const innerLen = i - 1 - innerStart
        return { raw, innerStart, innerLen }
      }
      if (c === '\\') {
        if (i + 1 >= text.length) return null
        const n = text[i + 1]!
        if (n === 'u') {
          if (i + 5 >= text.length) return null
          raw += text.slice(i, i + 6)
          i += 6
          continue
        }
        raw += c + n
        i += 2
        continue
      }
      if (c === '\n' || c === '\r') return null
      raw += c
      i++
    }
    return null
  }

  while (i < text.length) {
    skipWs()
    if (i >= text.length) break
    const ch = text[i]!

    if (ch === '{') {
      containers.push({ isObject: true, inheritKey: null, inheritKeyRaw: null })
      pendingKey = null
      pendingKeyRaw = null
      afterColon = false
      i++
      continue
    }
    if (ch === '[') {
      const inherit = valuePreceding()
      containers.push({
        isObject: false,
        inheritKey: inherit.key,
        inheritKeyRaw: inherit.keyRaw,
      })
      pendingKey = null
      pendingKeyRaw = null
      afterColon = false
      i++
      continue
    }
    if (ch === '}' || ch === ']') {
      if (containers.length === 0) return null
      containers.pop()
      pendingKey = null
      pendingKeyRaw = null
      afterColon = false
      i++
      continue
    }
    if (ch === ':') {
      afterColon = true
      i++
      continue
    }
    if (ch === ',') {
      afterColon = false
      pendingKey = null
      pendingKeyRaw = null
      i++
      continue
    }
    if (ch === '"') {
      const str = readString()
      if (!str) return null
      const decoded = decodeJsonStringContent(str.raw)
      const isKey = inObject() && !afterColon
      if (isKey) {
        pendingKey = decoded
        pendingKeyRaw = str.raw
        afterColon = false
        spans.push({
          kind: 'key',
          absOffset: bodyAbsOffset + str.innerStart,
          byteLength: str.innerLen,
          raw: str.raw,
          decoded,
          precedingKey: null,
          precedingKeyRaw: null,
        })
      } else {
        const prec = valuePreceding()
        spans.push({
          kind: 'string',
          absOffset: bodyAbsOffset + str.innerStart,
          byteLength: str.innerLen,
          raw: str.raw,
          decoded,
          precedingKey: prec.key,
          precedingKeyRaw: prec.keyRaw,
        })
        pendingKey = null
        pendingKeyRaw = null
        afterColon = false
      }
      continue
    }

    if (ch === '-' || (ch >= '0' && ch <= '9')) {
      const start = i
      i++
      while (i < text.length && /[0-9.eE+-]/.test(text[i]!)) i++
      const raw = text.slice(start, i)
      if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(raw)) return null
      const prec = valuePreceding()
      spans.push({
        kind: 'number',
        absOffset: bodyAbsOffset + start,
        byteLength: raw.length,
        raw,
        decoded: raw,
        precedingKey: prec.key,
        precedingKeyRaw: prec.keyRaw,
      })
      pendingKey = null
      pendingKeyRaw = null
      afterColon = false
      continue
    }

    if (ch === 't' || ch === 'f' || ch === 'n') {
      const lit =
        ch === 't' ? 'true' : ch === 'f' ? 'false' : 'null'
      if (text.slice(i, i + lit.length) !== lit) return null
      i += lit.length
      pendingKey = null
      pendingKeyRaw = null
      afterColon = false
      continue
    }

    return null
  }

  return containers.length === 0 ? spans : null
}

/**
 * String-value spans only (compat). Prefer {@link findJsonLexemeSpans} for full coverage.
 */
export function findJsonStringSpans(body: Uint8Array, bodyAbsOffset: number): JsonStringSpan[] | null {
  const lexemes = findJsonLexemeSpans(body, bodyAbsOffset)
  if (lexemes === null) return null
  return lexemes
    .filter((l) => l.kind === 'string')
    .map((l) => ({
      absOffset: l.absOffset,
      byteLength: l.byteLength,
      value: l.raw,
      precedingKey: l.precedingKey,
    }))
}

function maskBodyInPlace(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  bodyAbsOffset: number,
  bodyLength: number,
  fields: SensitiveField[],
): HttpBodySanitizeResult {
  if (bodyLength <= 0) {
    return { disposition: 'empty', coverageStatus: 'covered', fields }
  }
  fields.push({
    type: 'HTTP_BODY',
    start: bodyAbsOffset,
    length: bodyLength,
    classification: 'UNKNOWN_UNVERIFIED',
  })
  const fill = createProtocolNeutralMaskFill({
    length: bodyLength,
    packetIndex,
    offset: bodyAbsOffset,
    domain: 'http:body:unknown-unverified',
  })
  collector.add(bodyAbsOffset, fill)
  intents?.recordMaskRange(packetIndex, bodyAbsOffset, bodyLength, 'http-body-unverified', 'http')
  return {
    disposition: 'masked-unverified',
    coverageStatus: 'redacted',
    fields,
  }
}

/** Grammar-valid JSON text redaction (keys/strings); never binary mask fill. */
export function redactJsonLexemeBytes(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  absOffset: number,
  byteLength: number,
  padByte: number = JSON_LEXEME_REDACT_BYTE,
): void {
  if (byteLength <= 0) return
  patchFixedLengthAscii(collector, absOffset, byteLength, '', padByte)
  intents?.recordFixedRedaction(packetIndex, absOffset, byteLength)
}

/** Grammar-valid XML text/CDATA/attribute redaction. */
export function redactXmlTextBytes(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  absOffset: number,
  byteLength: number,
  domain: string,
  protocol: string,
  padByte: number = XML_TEXT_REDACT_BYTE,
): void {
  if (byteLength <= 0) return
  patchFixedLengthAscii(collector, absOffset, byteLength, '', padByte)
  intents?.recordMaskRange(packetIndex, absOffset, byteLength, domain, protocol)
}

function maskJsonLexemeInPlace(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  absOffset: number,
  byteLength: number,
  fields: SensitiveField[],
  fieldType: string,
  classification: FieldClassification,
): void {
  if (byteLength <= 0) return
  fields.push({
    type: fieldType,
    start: absOffset,
    length: byteLength,
    classification,
  })
  redactJsonLexemeBytes(collector, intents, packetIndex, absOffset, byteLength)
}

function maskJsonNumberInPlace(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  absOffset: number,
  raw: string,
  fields: SensitiveField[],
): void {
  if (raw.length <= 0) return
  fields.push({
    type: 'HTTP_JSON_NUMBER',
    start: absOffset,
    length: raw.length,
    classification: 'SECRET',
  })
  const masked = maskJsonNumberRaw(raw)
  const bytes = new Uint8Array(masked.length)
  for (let i = 0; i < masked.length; i++) bytes[i] = masked.charCodeAt(i) & 0xff
  collector.add(absOffset, bytes)
  intents?.recordFixedRedaction(packetIndex, absOffset, raw.length)
}

/**
 * Untyped JSON policy: every key/string/number leaf is dispositioned.
 * Unknown / dynamic keys → mask key + value; secret keys → mask values (incl. numbers);
 * public keys keep safe metadata / identity mapping.
 */
function tryStructuredJsonSanitize(
  body: Uint8Array,
  bodyAbsOffset: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  fields: SensitiveField[],
): HttpBodySanitizeResult | null {
  const lexemes = findJsonLexemeSpans(body, bodyAbsOffset)
  if (lexemes === null) return null

  fields.push({
    type: 'HTTP_BODY_JSON',
    start: bodyAbsOffset,
    length: body.length,
    classification: 'SAFE_METADATA',
  })

  for (const lex of lexemes) {
    if (lex.byteLength <= 0) continue

    if (lex.kind === 'key') {
      if (shouldMaskJsonKeyName(lex.decoded) || jsonKeyHasEscape(lex.raw)) {
        maskJsonLexemeInPlace(
          collector,
          intents,
          packetIndex,
          lex.absOffset,
          lex.byteLength,
          fields,
          'HTTP_JSON_KEY',
          'UNKNOWN_UNVERIFIED',
        )
      }
      continue
    }

    const key = lex.precedingKey
    const keyRaw = lex.precedingKeyRaw
    const keyIsSecret = key !== null && isJsonSecretKey(key)
    const keyIsPublic = key !== null && isJsonPublicKey(key) && !(keyRaw !== null && jsonKeyHasEscape(keyRaw))
    const keyIsUnknown = key === null || (!keyIsSecret && !keyIsPublic)

    if (lex.kind === 'number') {
      if (keyIsSecret || keyIsUnknown) {
        maskJsonNumberInPlace(collector, intents, packetIndex, lex.absOffset, lex.raw, fields)
      }
      continue
    }

    // string value — secret / identity first; unknown keys default to mask (never preserve).
    const kind = classifyJsonStringValue(lex.decoded)
    if (keyIsSecret || kind === 'secret-shaped') {
      maskJsonLexemeInPlace(
        collector,
        intents,
        packetIndex,
        lex.absOffset,
        lex.byteLength,
        fields,
        'HTTP_JSON_SECRET',
        'SECRET',
      )
      continue
    }

    if (kind !== null) {
      const category = kind
      const wire = lex.raw
      const constraint = { kind: 'text-ascii' as const, byteLength: lex.byteLength }
      fields.push({
        type: `HTTP_JSON_${category.toUpperCase()}`,
        start: lex.absOffset,
        length: lex.byteLength,
        classification: 'IDENTITY',
      })
      intents?.recordEntityReplacement(
        packetIndex,
        lex.absOffset,
        category,
        lex.decoded,
        lex.byteLength,
        constraint,
        wire,
      )
      collector.addDeferred(lex.absOffset, lex.byteLength, ({ mapping: live }) => {
        const mapped = live.aliasFor(category, lex.decoded, constraint, wire)
        if (mapped.length !== lex.byteLength) {
          return computeFixedLengthAsciiBytes(
            lex.absOffset,
            lex.byteLength,
            '',
            JSON_LEXEME_REDACT_BYTE,
          )
        }
        return computeFixedLengthAsciiBytes(lex.absOffset, lex.byteLength, mapped)
      })
      continue
    }

    if (keyIsUnknown) {
      maskJsonLexemeInPlace(
        collector,
        intents,
        packetIndex,
        lex.absOffset,
        lex.byteLength,
        fields,
        'HTTP_JSON_UNKNOWN',
        'UNKNOWN_UNVERIFIED',
      )
    }
  }

  return {
    disposition: 'structured-sanitized',
    coverageStatus: 'covered',
    fields,
  }
}

/**
 * Sanitize HTTP body bytes. Never leave unverified plaintext as passthrough.
 */
export function sanitizeHttpBody(input: {
  readonly buffer: Uint8Array
  readonly bodyAbsOffset: number
  readonly bodyLength: number
  readonly headers: HttpBodyHeaders
  readonly collector: PatchCollector
  readonly mapping: MappingLike
  readonly intents?: IntentCollector
  readonly packetIndex: number
  /** T15 — high-privacy masks free text after / instead of best-effort detectors. */
  readonly highPrivacy?: boolean
}): HttpBodySanitizeResult {
  const fields: SensitiveField[] = []
  const {
    bodyAbsOffset,
    bodyLength,
    headers,
    collector,
    mapping,
    intents,
    packetIndex,
    buffer,
    highPrivacy = false,
  } = input

  if (bodyLength <= 0) {
    return { disposition: 'empty', coverageStatus: 'covered', fields }
  }

  const body = buffer.subarray(bodyAbsOffset, bodyAbsOffset + bodyLength)

  // Compressed / unknown transfer framing → UNKNOWN_UNVERIFIED MASK (never decompress).
  if (isCompressedEncoding(headers.contentEncoding) || isChunked(headers.transferEncoding)) {
    return maskBodyInPlace(collector, intents, packetIndex, bodyAbsOffset, bodyLength, fields)
  }

  if (isJsonContentType(headers.contentType)) {
    const structured = tryStructuredJsonSanitize(
      body,
      bodyAbsOffset,
      collector,
      intents,
      packetIndex,
      fields,
    )
    if (structured) return structured
    return maskBodyInPlace(collector, intents, packetIndex, bodyAbsOffset, bodyLength, fields)
  }

  // T55 — CWMP SOAP (TR-069) before generic text/* / unverified mask.
  {
    const fullText = new TextDecoder('latin1').decode(body)
    if (cwmpSoapEligible(headers.contentType, fullText)) {
      const cwmp = sanitizeCwmpSoapBody(
        buffer,
        bodyAbsOffset,
        bodyLength,
        collector,
        mapping,
        intents,
        packetIndex,
      )
      fields.push({
        type: 'HTTP_BODY_CWMP',
        start: bodyAbsOffset,
        length: bodyLength,
        classification: 'IDENTITY',
      })
      return {
        disposition: 'structured-sanitized',
        coverageStatus: 'covered',
        fields,
        childCoverage: cwmp.coverage,
        issues: cwmp.issues,
      }
    }
  }

  // T15 — text/* bodies: same builtin detectors as text logs (best-effort / heuristic).
  if (isPlainTextContentType(headers.contentType)) {
    fields.push({
      type: 'HTTP_BODY_TEXT',
      start: bodyAbsOffset,
      length: bodyLength,
      classification: highPrivacy ? 'UNKNOWN_UNVERIFIED' : 'IDENTITY',
    })
    const result = sanitizeTextPayload({
      buffer,
      absoluteOffset: bodyAbsOffset,
      byteLength: bodyLength,
      collector,
      mapping,
      intents,
      packetIndex,
      highPrivacy,
      protocolId: 'http-text',
    })
    return {
      disposition: result.coverageStatus === 'redacted' ? 'masked-unverified' : 'structured-sanitized',
      coverageStatus: result.coverageStatus,
      fields,
    }
  }

  // Any other body (including missing Content-Type) is unverified plaintext.
  return maskBodyInPlace(collector, intents, packetIndex, bodyAbsOffset, bodyLength, fields)
}

export function httpBodyFieldClassifications(fields: readonly SensitiveField[]): FieldClassification[] {
  return fields.map((f) => f.classification)
}
