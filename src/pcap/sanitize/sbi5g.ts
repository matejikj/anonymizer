/**
 * T61 — 5G SBI (HTTP/JSON + multipart N1/N2) over cleartext HTTP/1.x and h2c DATA.
 * Pinned REL-18 field policy; N1 → T59, typed N2 → T58 schemaTypeId (not whole-PDU guess).
 */

import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import type { PatchCollector } from './PatchCollector.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { computeFixedLengthAsciiBytes } from './textPatch.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import { canonicalizePcapIdentity } from '../../mapping/pcapCanonical.ts'
import type { IdentityCategory } from '../../mapping/identityCategories.ts'
import {
  findJsonLexemeSpans,
  jsonKeyHasEscape,
  JSON_LEXEME_REDACT_BYTE,
  maskJsonNumberRaw,
  redactJsonLexemeBytes,
  type JsonLexemeSpan,
} from './httpBody.ts'
import { sanitizeNas, looksLikeNas } from './nas.ts'
import { sanitizeN2Transfer, type N2TransferSchemaId } from './ngap.ts'
import {
  looksLikeSbiPath,
  sbiFamilyFromPath,
  SBI_FIELD_POLICY,
  SBI_PINNED_OPERATIONS,
  SBI_SCHEMA_PIN,
  type SbiApiFamily,
  type SbiFieldAction,
} from '../protocols/sbi/schemaInventory.ts'

export { SBI_PINNED_OPERATIONS, SBI_SCHEMA_PIN, looksLikeSbiPath, sbiFamilyFromPath }

const TEXT_DEC = new TextDecoder('ascii', { fatal: false })
const TEXT_ENC = new TextEncoder()

const N2_SCHEMA_ALIASES: ReadonlyMap<string, N2TransferSchemaId> = new Map([
  [
    'pdusessionresourcesetuprequesttransfer',
    'ngap.PDUSessionResourceSetupRequestTransfer',
  ],
  [
    'pdusessionresourcesetupresponsetransfer',
    'ngap.PDUSessionResourceSetupResponseTransfer',
  ],
  [
    'ngap.pdusessionresourcesetuprequesttransfer',
    'ngap.PDUSessionResourceSetupRequestTransfer',
  ],
  [
    'ngap.pdusessionresourcesetupresponsetransfer',
    'ngap.PDUSessionResourceSetupResponseTransfer',
  ],
])

export function looksLikeSbi(
  buffer: Uint8Array,
  offset: number,
  length: number,
): boolean {
  if (length < 16) return false
  const head = TEXT_DEC.decode(buffer.subarray(offset, offset + Math.min(length, 512)))
  if (/^(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) /i.test(head)) {
    const lineEnd = head.indexOf('\r\n')
    const start = lineEnd >= 0 ? head.slice(0, lineEnd) : head
    if (looksLikeSbiPath(start)) return true
  }
  if (/^HTTP\/1\.[01] /i.test(head) && /3gpp|nnrf-|namf-|nsmf-|nudm-|nausf-|npcf-/i.test(head)) {
    return true
  }
  return looksLikeSbiJsonBody(buffer, offset, length)
}

/** Content probe for h2c DATA / bare JSON bodies (HPACK not available). */
export function looksLikeSbiJsonBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
): boolean {
  if (length < 8) return false
  const slice = buffer.subarray(offset, offset + Math.min(length, 256))
  const t = TEXT_DEC.decode(slice).trimStart()
  if (!t.startsWith('{') && !t.startsWith('[')) return false
  return /"(?:supi|gpsi|pei|nfInstanceId|nfInstanceID|accessToken|smContextRef|ueContextId|n1MessageContainer|n2InfoContainer)"/i.test(
    t,
  )
}

export function sanitizeSbi5g(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeSbi(buffer, offset, length)) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const head = TEXT_DEC.decode(buffer.subarray(offset, offset + Math.min(length, 8192)))

  if (/^(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|HTTP\/)/i.test(head)) {
    const headerEndIdx = head.indexOf('\r\n\r\n')
    if (headerEndIdx < 0) {
      coverage.push({
        protocol: 'sbi5g',
        offset,
        length,
        status: 'requires-reassembly',
      })
      return { coverage, issues: ['sbi5g-headers-incomplete'] }
    }
    const headerBlockLen = headerEndIdx + 4
    const headerText = head.slice(0, headerEndIdx)
    const lines = headerText.split('\r\n')
    const startLine = lines[0] ?? ''
    const family = familyFromStartLine(startLine)
    coverage.push({
      protocol: family === 'unknown' ? 'sbi5g' : `sbi5g-${family}`,
      offset,
      length: headerBlockLen,
      status: 'covered',
    })

    sanitizeHttpStartAndHeaders(
      buffer,
      offset,
      lines,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
    )

    const bodyOff = offset + headerBlockLen
    const bodyLen = length - headerBlockLen
    if (bodyLen > 0) {
      const ct = contentTypeFromLines(lines)
      if (ct.includes('multipart/')) {
        sanitizeMultipart(
          buffer,
          bodyOff,
          bodyLen,
          ct,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
          issues,
        )
      } else if (ct.includes('json') || looksLikeSbiJsonBody(buffer, bodyOff, bodyLen)) {
        sanitizeSbiJsonBody(
          buffer,
          bodyOff,
          bodyLen,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
          issues,
        )
      } else if (ct.includes('vnd.3gpp.5gnas') || looksLikeNas(buffer, bodyOff, bodyLen)) {
        nestNas(buffer, bodyOff, bodyLen, collector, mapping, intents, packetIndex, coverage, issues)
      } else if (ct.includes('vnd.3gpp.ngap')) {
        nestN2(
          buffer,
          bodyOff,
          bodyLen,
          ct,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
          issues,
        )
      } else {
        maskSpan(collector, intents, packetIndex, bodyOff, bodyLen, 'sbi5g-body-unknown')
        coverage.push({
          protocol: 'sbi5g-body',
          offset: bodyOff,
          length: bodyLen,
          status: 'redacted',
        })
        issues.push('sbi5g-unknown-content-type')
      }
    }
    return { coverage, issues }
  }

  // Bare JSON (h2c DATA path)
  sanitizeSbiJsonBody(
    buffer,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
  )
  return coverage.length ? { coverage, issues } : null
}

/** Called from HTTP/2 DATA frames when JSON looks like SBI. */
export function sanitizeSbiJsonBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[] = [],
  issues: string[] = [],
): AppLayerResult {
  const body = buffer.subarray(offset, offset + length)
  const lexemes = findJsonLexemeSpans(body, offset)
  if (!lexemes) {
    maskJsonTextSpan(collector, intents, packetIndex, offset, length, 'sbi5g-json-unparseable')
    coverage.push({
      protocol: 'sbi5g-json',
      offset,
      length,
      status: 'malformed',
    })
    issues.push('sbi5g-json-unparseable')
    return { coverage, issues }
  }

  let allDispositioned = true
  for (const lex of lexemes) {
    if (!dispositionSbiJsonLexeme(
      buffer,
      lex,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
    )) {
      allDispositioned = false
    }
  }
  coverage.push({
    protocol: 'sbi5g-json',
    offset,
    length,
    status: allDispositioned ? 'covered' : 'redacted',
  })
  if (!allDispositioned) issues.push('sbi5g-json-incomplete-disposition')
  return { coverage, issues }
}

/**
 * Apply schema/operation field policy to one lexeme. Unknown keys → mask key + value.
 * Escaped keys never receive preserve (unicode bypass). Returns false if left untouched unsafely.
 */
function dispositionSbiJsonLexeme(
  buffer: Uint8Array,
  lex: JsonLexemeSpan,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): boolean {
  if (lex.byteLength <= 0) return true

  if (lex.kind === 'key') {
    if (!isKnownSbiField(lex.decoded) || jsonKeyHasEscape(lex.raw)) {
      maskJsonTextSpan(
        collector,
        intents,
        packetIndex,
        lex.absOffset,
        lex.byteLength,
        'sbi5g-json-key',
      )
      coverage.push({
        protocol: 'sbi5g-mask',
        offset: lex.absOffset,
        length: lex.byteLength,
        status: 'redacted',
      })
    }
    return true
  }

  const key = lex.precedingKey
  const keyRaw = lex.precedingKeyRaw
  if (!key) {
    // Root-array leaf without inherited key — fail closed.
    if (lex.kind === 'number') {
      maskJsonNumberSpan(collector, intents, packetIndex, lex.absOffset, lex.raw)
    } else {
      maskJsonTextSpan(
        collector,
        intents,
        packetIndex,
        lex.absOffset,
        lex.byteLength,
        'sbi5g-json-orphan',
      )
    }
    coverage.push({
      protocol: 'sbi5g-mask',
      offset: lex.absOffset,
      length: lex.byteLength,
      status: 'redacted',
    })
    return true
  }

  let action = resolveFieldAction(key)
  // Escaped wire keys must not inherit preserve from decoded schema names.
  if (action === 'preserve' && keyRaw !== null && jsonKeyHasEscape(keyRaw)) {
    action = 'mask'
  }

  if (lex.kind === 'number') {
    if (action === 'preserve') return true
    maskJsonNumberSpan(collector, intents, packetIndex, lex.absOffset, lex.raw)
    coverage.push({
      protocol:
        key.toLowerCase().includes('token') || /rand|autn|xres|kseaf|secret/i.test(key)
          ? 'sbi5g-auth'
          : 'sbi5g-mask',
      offset: lex.absOffset,
      length: lex.byteLength,
      status: 'redacted',
    })
    return true
  }

  // string value
  if (action === 'preserve') return true
  applyStringAction(
    buffer,
    lex.absOffset,
    lex.byteLength,
    lex.decoded,
    action,
    key,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
  )
  return true
}

function maskJsonNumberSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  raw: string,
): void {
  if (raw.length <= 0) return
  const masked = maskJsonNumberRaw(raw)
  const bytes = new Uint8Array(masked.length)
  for (let i = 0; i < masked.length; i++) bytes[i] = masked.charCodeAt(i) & 0xff
  try {
    collector.add(offset, bytes)
  } catch {
    /* overlap */
  }
  intents?.recordFixedRedaction(packetIndex, offset, raw.length)
}

function isKnownSbiField(key: string): boolean {
  if (SBI_FIELD_POLICY.has(key)) return true
  const lower = key.toLowerCase()
  for (const k of SBI_FIELD_POLICY.keys()) {
    if (k.toLowerCase() === lower) return true
  }
  return false
}

function familyFromStartLine(startLine: string): SbiApiFamily {
  const m = /^(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) (\S+)/i.exec(startLine)
  if (!m) return 'unknown'
  return sbiFamilyFromPath(m[1]!)
}

function contentTypeFromLines(lines: readonly string[]): string {
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!
    const colon = line.indexOf(':')
    if (colon < 0) continue
    if (line.slice(0, colon).trim().toLowerCase() !== 'content-type') continue
    return line.slice(colon + 1).trim().toLowerCase()
  }
  return ''
}

function sanitizeHttpStartAndHeaders(
  buffer: Uint8Array,
  msgOffset: number,
  lines: readonly string[],
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const startLine = lines[0] ?? ''
  const req = /^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) (\S+) (HTTP\/1\.[01])$/i.exec(startLine)
  if (req) {
    const method = req[1]!
    const target = req[2]!
    const targetOff = msgOffset + method.length + 1
    sanitizeRequestTarget(
      buffer,
      targetOff,
      target,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
    )
  }

  let cursor = (lines[0]?.length ?? 0) + 2
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!
    const abs = msgOffset + cursor
    const colon = line.indexOf(':')
    if (colon > 0) {
      const name = line.slice(0, colon).trim().toLowerCase()
      let valueStart = colon + 1
      if (line[valueStart] === ' ') valueStart++
      const valueAbs = abs + valueStart
      const valueLen = line.length - valueStart
      if (
        name === 'authorization'
        || name === 'proxy-authorization'
        || name === '3gpp-sbi-access-token'
      ) {
        maskSpan(collector, intents, packetIndex, valueAbs, valueLen, 'sbi5g-auth')
        coverage.push({
          protocol: 'sbi5g-auth',
          offset: valueAbs,
          length: valueLen,
          status: 'redacted',
        })
        issues.push('sbi5g-token-masked')
      } else if (
        name === 'location'
        || name === '3gpp-sbi-target-apiroot'
        || name === '3gpp-sbi-binding'
        || name === '3gpp-sbi-callback'
      ) {
        mapAscii(
          buffer,
          valueAbs,
          valueLen,
          'opaque-id',
          collector,
          mapping,
          intents,
          packetIndex,
          'sbi5g-hdr:',
        )
        coverage.push({
          protocol: 'sbi5g-uri',
          offset: valueAbs,
          length: valueLen,
          status: 'covered',
        })
      } else if (name === 'host') {
        mapAscii(
          buffer,
          valueAbs,
          valueLen,
          'hostname',
          collector,
          mapping,
          intents,
          packetIndex,
        )
        coverage.push({
          protocol: 'sbi5g-host',
          offset: valueAbs,
          length: valueLen,
          status: 'covered',
        })
      }
    }
    cursor += line.length + 2
  }
}

function sanitizeRequestTarget(
  buffer: Uint8Array,
  targetOff: number,
  target: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const qIdx = target.indexOf('?')
  const path = qIdx >= 0 ? target.slice(0, qIdx) : target
  const query = qIdx >= 0 ? target.slice(qIdx + 1) : ''

  // Map sensitive path segments (UE/NF IDs), preserve service literals
  const parts = path.split('/')
  let partOff = targetOff
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!
    if (i > 0) partOff += 1
    if (
      part.length > 0
      && !/^(?:nnrf|namf|nsmf|nudm|nausf|npcf|nnssf|nnef)-/i.test(part)
      && !/^v\d+$/i.test(part)
      && !/^(?:nf-instances|ue-contexts|sm-contexts|subscriptions|ue-authentications|sm-policies|network-slice-information|n1-n2-messages|modify|release|registrations|amf-3gpp-access|oauth2|token)$/i.test(
        part,
      )
    ) {
      const action: SbiFieldAction =
        /^imsi-/i.test(part) || /^\d{5,15}$/.test(part) ? 'map-imsi' : 'map-opaque'
      applyStringAction(
        buffer,
        partOff,
        part.length,
        part,
        action,
        'pathSegment',
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    }
    partOff += part.length
  }

  if (query.length > 0) {
    const queryOff = targetOff + path.length + 1
    let pos = 0
    while (pos < query.length) {
      let amp = query.indexOf('&', pos)
      if (amp < 0) amp = query.length
      const pair = query.slice(pos, amp)
      const eq = pair.indexOf('=')
      const key = (eq >= 0 ? pair.slice(0, eq) : pair)
      if (eq >= 0) {
        const valOff = queryOff + pos + eq + 1
        const valLen = pair.length - eq - 1
        const val = pair.slice(eq + 1)
        if (valLen > 0) {
          const action = resolveFieldAction(key)
          if (action !== 'preserve') {
            applyStringAction(
              buffer,
              valOff,
              valLen,
              decodeUriComponentSafe(val),
              action,
              key,
              collector,
              mapping,
              intents,
              packetIndex,
              coverage,
              issues,
            )
          }
        }
      }
      pos = amp + 1
    }
  }
}

function sanitizeMultipart(
  buffer: Uint8Array,
  offset: number,
  length: number,
  contentType: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const boundary = extractBoundary(contentType)
  if (!boundary) {
    maskSpan(collector, intents, packetIndex, offset, length, 'sbi5g-multipart-noboundary')
    coverage.push({
      protocol: 'sbi5g-multipart',
      offset,
      length,
      status: 'malformed',
    })
    issues.push('sbi5g-multipart-no-boundary')
    return
  }

  coverage.push({ protocol: 'sbi5g-multipart', offset, length, status: 'covered' })
  const body = TEXT_DEC.decode(buffer.subarray(offset, offset + length))
  const delim = `--${boundary}`
  let searchFrom = 0
  while (searchFrom < body.length) {
    const start = body.indexOf(delim, searchFrom)
    if (start < 0) break
    let partStart = start + delim.length
    if (body.startsWith('--', partStart)) break // final
    if (body.startsWith('\r\n', partStart)) partStart += 2
    else if (body.startsWith('\n', partStart)) partStart += 1

    const next = body.indexOf(delim, partStart)
    const partEnd = next < 0 ? body.length : next
    // trim trailing CRLF before next boundary
    let contentEnd = partEnd
    if (contentEnd >= 2 && body.slice(contentEnd - 2, contentEnd) === '\r\n') contentEnd -= 2

    const partText = body.slice(partStart, contentEnd)
    const sep = partText.indexOf('\r\n\r\n')
    if (sep < 0) {
      // No header/body separator — mask entire part (preamble/epilogue/malformed).
      const partAbs = offset + partStart
      const partLen = contentEnd - partStart
      if (partLen > 0) {
        maskSpan(collector, intents, packetIndex, partAbs, partLen, 'sbi5g-mime-malformed')
        coverage.push({
          protocol: 'sbi5g-mime',
          offset: partAbs,
          length: partLen,
          status: 'redacted',
        })
        issues.push('sbi5g-mime-part-malformed')
      }
      searchFrom = partEnd
      continue
    }
    const partHeaders = partText.slice(0, sep)
    const partHeadersAbs = offset + partStart
    sanitizeMimePartHeaders(
      buffer,
      partHeadersAbs,
      partHeaders,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
    )
    const partBodyRel = partStart + sep + 4
    const partBodyAbs = offset + partBodyRel
    const partBodyLen = contentEnd - (partStart + sep + 4)
    const partCt = headerValue(partHeaders, 'content-type')?.toLowerCase() ?? ''

    if (partCt.includes('json') || looksLikeSbiJsonBody(buffer, partBodyAbs, partBodyLen)) {
      sanitizeSbiJsonBody(
        buffer,
        partBodyAbs,
        partBodyLen,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    } else if (partCt.includes('vnd.3gpp.5gnas') || looksLikeNas(buffer, partBodyAbs, partBodyLen)) {
      nestNas(
        buffer,
        partBodyAbs,
        partBodyLen,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    } else if (partCt.includes('vnd.3gpp.ngap')) {
      nestN2(
        buffer,
        partBodyAbs,
        partBodyLen,
        partCt,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    } else if (partBodyLen > 0) {
      maskSpan(collector, intents, packetIndex, partBodyAbs, partBodyLen, 'sbi5g-mime-unknown')
      coverage.push({
        protocol: 'sbi5g-mime',
        offset: partBodyAbs,
        length: partBodyLen,
        status: 'redacted',
      })
      issues.push('sbi5g-unknown-mime-part')
    }
    searchFrom = partEnd
  }
}

function nestNas(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (looksLikeNas(buffer, offset, length)) {
    const nas = sanitizeNas(buffer, offset, length, collector, mapping, intents, packetIndex)
    if (nas) {
      coverage.push(...nas.coverage.map((c) => ({ ...c, protocol: `sbi5g-n1:${c.protocol}` })))
      if (nas.issues) for (const i of nas.issues) issues.push(i)
      return
    }
  }
  maskSpan(collector, intents, packetIndex, offset, length, 'sbi5g-n1-opaque')
  coverage.push({
    protocol: 'sbi5g-n1',
    offset,
    length,
    status: 'redacted',
  })
  issues.push('sbi5g-n1-opaque')
}

function nestN2(
  buffer: Uint8Array,
  offset: number,
  length: number,
  contentType: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  const schemaId = n2SchemaFromContentType(contentType)
  if (!schemaId) {
    maskSpan(collector, intents, packetIndex, offset, length, 'sbi5g-n2-unsupported')
    coverage.push({
      protocol: 'sbi5g-n2-unsupported',
      offset,
      length,
      status: 'unsupported',
    })
    issues.push('sbi5g-n2-schema-unknown')
    return
  }
  const n2 = sanitizeN2Transfer(
    schemaId,
    buffer,
    offset,
    length,
    collector,
    mapping,
    intents,
    packetIndex,
  )
  if (n2) {
    coverage.push(...n2.coverage.map((c) => ({ ...c, protocol: `sbi5g-n2:${c.protocol}` })))
    if (n2.issues) for (const i of n2.issues) issues.push(i)
    return
  }
  maskSpan(collector, intents, packetIndex, offset, length, 'sbi5g-n2-fail')
  coverage.push({
    protocol: 'sbi5g-n2',
    offset,
    length,
    status: 'malformed',
  })
  issues.push('sbi5g-n2-sanitize-fail')
}

function n2SchemaFromContentType(ct: string): N2TransferSchemaId | undefined {
  const typeParam = /(?:^|;)\s*type\s*=\s*"?([^";]+)"?/i.exec(ct)
  if (!typeParam) return undefined
  const key = typeParam[1]!.trim().toLowerCase()
  return N2_SCHEMA_ALIASES.get(key)
}

function resolveFieldAction(key: string): SbiFieldAction {
  const direct = SBI_FIELD_POLICY.get(key)
  if (direct) return direct
  const lower = key.toLowerCase()
  for (const [k, v] of SBI_FIELD_POLICY) {
    if (k.toLowerCase() === lower) return v
  }
  // Unknown keys: mask values (additionalProperties not public)
  return 'mask'
}

function applyStringAction(
  buffer: Uint8Array,
  offset: number,
  length: number,
  value: string,
  action: SbiFieldAction,
  key: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (length <= 0 || action === 'preserve') return
  if (action === 'mask') {
    maskJsonTextSpan(collector, intents, packetIndex, offset, length, `sbi5g-${key}`)
    coverage.push({
      protocol: key.toLowerCase().includes('token') || /rand|autn|xres|kseaf|secret/i.test(key)
        ? 'sbi5g-auth'
        : 'sbi5g-mask',
      offset,
      length,
      status: 'redacted',
    })
    return
  }
  if (action === 'map-ipv4') {
    mapAscii(buffer, offset, length, 'ipv4', collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'sbi5g-ip', offset, length, status: 'covered' })
    return
  }
  if (action === 'map-hostname') {
    // Callback URLs may contain tokens in query — mask whole URI string for safety
    if (/[?&](?:access_?token|token)=/i.test(value) || value.includes('Bearer')) {
      maskJsonTextSpan(collector, intents, packetIndex, offset, length, 'sbi5g-uri-token')
      coverage.push({
        protocol: 'sbi5g-auth',
        offset,
        length,
        status: 'redacted',
      })
      issues.push('sbi5g-callback-token-masked')
      return
    }
    mapAscii(buffer, offset, length, 'opaque-id', collector, mapping, intents, packetIndex, 'sbi5g-uri:')
    coverage.push({ protocol: 'sbi5g-uri', offset, length, status: 'covered' })
    return
  }
  if (action === 'map-imsi') {
    const digits = value.replace(/^imsi-/i, '').replace(/\D/g, '')
    if (digits.length >= 5 && digits.length <= 15) {
      mapAscii(buffer, offset, length, 'imsi', collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'sbi5g-supi', offset, length, status: 'covered' })
      return
    }
    mapAscii(buffer, offset, length, 'opaque-id', collector, mapping, intents, packetIndex, 'sbi5g-ue:')
    coverage.push({ protocol: 'sbi5g-ue', offset, length, status: 'covered' })
    return
  }
  // map-opaque
  mapAscii(buffer, offset, length, 'opaque-id', collector, mapping, intents, packetIndex, 'sbi5g:')
  coverage.push({ protocol: 'sbi5g-id', offset, length, status: 'covered' })
}

function mapAscii(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: IdentityCategory,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  canonicalPrefix?: string,
): void {
  if (length <= 0) return
  const raw = TEXT_DEC.decode(buffer.subarray(offset, offset + length))
  const token = raw.replace(/\0+$/g, '')
  if (!token) {
    maskJsonTextSpan(collector, intents, packetIndex, offset, length, 'sbi5g-empty')
    return
  }
  let forCanon = canonicalPrefix ? `${canonicalPrefix}${token}` : token
  if (category === 'imsi') {
    forCanon = token.replace(/^imsi-/i, '').replace(/\D/g, '') || token
  }
  const canon =
    (category === 'ipv4'
      ? canonicalizePcapIdentity('ipv4', token)
      : canonicalizeIdentity(category, forCanon)) ?? forCanon
  const constraint = { kind: 'text-ascii' as const, byteLength: length }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, length, constraint, token)
  try {
    collector.addDeferred(
      offset,
      length,
      ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(
            offset,
            length,
            live.aliasFor(category, canon, constraint, token),
          )
        } catch {
          return computeFixedLengthAsciiBytes(offset, length, '', JSON_LEXEME_REDACT_BYTE)
        }
      },
      { fallbackKind: 'text-x', protocol: 'sbi5g', category, packetIndex },
    )
  } catch {
    /* overlap */
  }
  void mapping
  void buffer
}

/**
 * V02 — MIME part headers: Content-Type preserve; Content-ID / unknown / tokens mask.
 * Values are length-preserved; header names stay for framing.
 */
function sanitizeMimePartHeaders(
  buffer: Uint8Array,
  headersAbs: number,
  headersText: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  let cursor = 0
  const lines = headersText.split(/\r\n/)
  for (const line of lines) {
    if (line.length === 0) {
      cursor += 2
      continue
    }
    const colon = line.indexOf(':')
    if (colon > 0) {
      const name = line.slice(0, colon).trim().toLowerCase()
      let valueStart = colon + 1
      if (line[valueStart] === ' ') valueStart++
      const valueAbs = headersAbs + cursor + valueStart
      const valueLen = line.length - valueStart
      if (
        name === 'content-type'
        || name === 'content-length'
        || name === 'content-transfer-encoding'
      ) {
        coverage.push({
          protocol: 'sbi5g-mime-hdr',
          offset: headersAbs + cursor,
          length: line.length,
          status: 'covered',
        })
      } else {
        // Content-ID, X-Private-Token, unknown — mask value
        maskSpan(collector, intents, packetIndex, valueAbs, valueLen, 'sbi5g-mime-hdr')
        coverage.push({
          protocol: 'sbi5g-mime-hdr',
          offset: valueAbs,
          length: valueLen,
          status: 'redacted',
        })
        issues.push('sbi5g-mime-header-masked')
      }
    } else if (line.length > 0) {
      maskSpan(collector, intents, packetIndex, headersAbs + cursor, line.length, 'sbi5g-mime-hdr')
      coverage.push({
        protocol: 'sbi5g-mime-hdr',
        offset: headersAbs + cursor,
        length: line.length,
        status: 'redacted',
      })
    }
    cursor += line.length + 2
  }
  void buffer
  void mapping
}

function maskJsonTextSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  try {
    redactJsonLexemeBytes(collector, intents, packetIndex, offset, length)
    intents?.recordMaskRange(packetIndex, offset, length, domain, 'sbi5g')
  } catch {
    /* overlap */
  }
}

function maskSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  try {
    // R06 — HTTP/MIME text spans stay valid UTF-8 (ASCII mask), not binary mask fill.
    collector.addDeferred(offset, length, () =>
      computeFixedLengthAsciiBytes(offset, length, '', JSON_LEXEME_REDACT_BYTE),
    )
  } catch {
    /* overlap */
  }
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'sbi5g')
}

function extractBoundary(contentType: string): string | null {
  const m = /boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i.exec(contentType)
  return m?.[1] ?? m?.[2] ?? null
}

function headerValue(headers: string, name: string): string | undefined {
  const re = new RegExp(`^${name}\\s*:\\s*(.+)$`, 'im')
  const m = re.exec(headers)
  return m?.[1]?.trim()
}

function decodeUriComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '))
  } catch {
    return s
  }
}

void TEXT_ENC
