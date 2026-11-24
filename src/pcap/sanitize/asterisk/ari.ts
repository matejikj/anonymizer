/**
 * T50 — Asterisk REST Interface (ARI): HTTP /ari/* + JSON bodies; api_key / resource IDs.
 * Headers use shared textproto HTTP policy (Cookie/auth/unknown → mask); never bypass HTTP protection.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { sanitizeHttpBody } from '../httpBody.ts'
import {
  dispositionForTextProtoHeader,
  tokenizeTextProtoMessage,
} from '../../protocols/application/textproto/index.ts'
import { decodeAscii, mapAsciiIdentity, maskBytes } from './common.ts'
import { ARI_HTTP_HEADER_POLICY } from './ariHeaderPolicy.ts'

export const ARI_HTTP_PORT = 8088

const ARI_PATH_RE = /\/ari(?:\/|$)/i

export function isAriPortHint(src: number, dst: number): boolean {
  return src === ARI_HTTP_PORT || dst === ARI_HTTP_PORT
}

export function looksLikeAri(
  buffer: Uint8Array,
  offset: number,
  length: number,
): boolean {
  if (length < 12) return false
  const head = decodeAscii(buffer, offset, Math.min(length, 256))
  if (!/^(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) /i.test(head)) return false
  const lineEnd = head.indexOf('\r\n')
  const start = lineEnd >= 0 ? head.slice(0, lineEnd) : head
  return ARI_PATH_RE.test(start)
}

export function sanitizeAri(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isAriPortHint(srcPort, dstPort) && !looksLikeAri(buffer, offset, length)) return null
  if (!looksLikeAri(buffer, offset, length) && !isAriPortHint(srcPort, dstPort)) return null
  // Port hint alone is not enough — require /ari/ in start line when present as HTTP
  if (!looksLikeAri(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const msg = tokenizeTextProtoMessage(buffer, offset, length)
  if (!msg) {
    coverage.push({
      protocol: 'ari',
      offset,
      length,
      status: 'requires-reassembly',
    })
    return { coverage, issues: ['ari-headers-incomplete'] }
  }

  const headerBlockLen = msg.headerBlockEnd - offset
  coverage.push({ protocol: 'ari', offset, length: headerBlockLen, status: 'covered' })

  sanitizeRequestLine(
    buffer,
    offset,
    msg.startLineText,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
  )

  for (const h of msg.headers) {
    const valueAbs = h.valueSpan.offset
    const valueLen = h.valueSpan.length
    if (valueLen <= 0) continue
    const action = dispositionForTextProtoHeader(ARI_HTTP_HEADER_POLICY, h.name)
    switch (action.kind) {
      case 'preserve':
      case 'structural':
        break
      case 'map':
        mapAsciiIdentity(
          buffer,
          valueAbs,
          valueLen,
          action.category === 'hostname' ? 'hostname' : 'opaque-id',
          collector,
          mapping,
          intents,
          packetIndex,
          'ari',
        )
        coverage.push({
          protocol: 'ari-id',
          offset: valueAbs,
          length: valueLen,
          status: 'covered',
        })
        break
      case 'credential':
      case 'mask':
      case 'detectors':
        maskBytes(
          collector,
          intents,
          packetIndex,
          valueAbs,
          valueLen,
          action.kind === 'credential' ? 'ari-auth' : 'ari-header',
          'ari',
        )
        coverage.push({
          protocol: action.kind === 'credential' ? 'ari-auth' : 'ari-header',
          offset: valueAbs,
          length: valueLen,
          status: 'redacted',
        })
        if (action.kind === 'credential' || h.name === 'cookie' || h.name.includes('token')) {
          issues.push('ari-header-masked')
        }
        break
      default:
        maskBytes(collector, intents, packetIndex, valueAbs, valueLen, 'ari-header', 'ari')
        coverage.push({
          protocol: 'ari-header',
          offset: valueAbs,
          length: valueLen,
          status: 'redacted',
        })
        break
    }
  }

  const bodyOff = msg.body?.offset ?? msg.headerBlockEnd
  const bodyLen = msg.body?.length ?? Math.max(0, offset + length - msg.headerBlockEnd)
  if (bodyLen > 0) {
    // Prefer JSON structured sanitize (secrets + phones via detectors)
    const bodyResult = sanitizeHttpBody({
      buffer,
      bodyAbsOffset: bodyOff,
      bodyLength: bodyLen,
      headers: { contentType: 'application/json', contentEncoding: null, transferEncoding: null },
      collector,
      mapping,
      intents,
      packetIndex,
      highPrivacy,
    })
    coverage.push({
      protocol: 'ari-json',
      offset: bodyOff,
      length: bodyLen,
      status: bodyResult.coverageStatus,
    })
    // Overlay ARI resource string fields
    sanitizeAriJsonStrings(
      buffer,
      bodyOff,
      bodyLen,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
    )
  }

  coverage.push({ protocol: 'ari', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeRequestLine(
  buffer: Uint8Array,
  msgOffset: number,
  startLine: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  // METHOD SP request-target SP HTTP/1.x
  const m = /^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD) (\S+) (HTTP\/1\.[01])$/i.exec(startLine)
  if (!m) {
    coverage.push({
      protocol: 'ari',
      offset: msgOffset,
      length: startLine.length,
      status: 'covered',
    })
    return
  }
  const method = m[1]!
  const target = m[2]!
  const targetOff = msgOffset + method.length + 1

  // Split path?query
  const qIdx = target.indexOf('?')
  const path = qIdx >= 0 ? target.slice(0, qIdx) : target
  const query = qIdx >= 0 ? target.slice(qIdx + 1) : ''

  // Map /ari/channels/{id}/… path segments after /ari/
  const parts = path.split('/')
  let partOff = targetOff
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!
    if (i > 0) partOff += 1 // slash
    if (
      part.length > 0
      && part.toLowerCase() !== 'ari'
      && !/^(?:channels|bridges|endpoints|applications|playbacks|recordings|sounds|deviceStates|mailboxes|events|asterisk)$/i.test(
        part,
      )
    ) {
      // Resource id segment
      mapAsciiIdentity(
        buffer,
        partOff,
        part.length,
        'opaque-id',
        collector,
        mapping,
        intents,
        packetIndex,
        'ari',
        'ari-res:',
      )
      coverage.push({
        protocol: 'ari-id',
        offset: partOff,
        length: part.length,
        status: 'covered',
      })
    }
    partOff += part.length
  }

  if (query.length > 0) {
    const queryOff = targetOff + path.length + 1
    sanitizeQuery(buffer, queryOff, query, collector, mapping, intents, packetIndex, coverage, issues)
  }
}

function sanitizeQuery(
  buffer: Uint8Array,
  offset: number,
  query: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  let pos = 0
  while (pos < query.length) {
    let amp = query.indexOf('&', pos)
    if (amp < 0) amp = query.length
    const pair = query.slice(pos, amp)
    const eq = pair.indexOf('=')
    const key = (eq >= 0 ? pair.slice(0, eq) : pair).toLowerCase()
    if (eq >= 0) {
      const valOff = offset + pos + eq + 1
      const valLen = pair.length - eq - 1
      if (valLen > 0) {
        if (key === 'api_key' || key === 'api-key' || key === 'password' || key === 'secret') {
          maskBytes(collector, intents, packetIndex, valOff, valLen, 'ari-secret', 'ari')
          coverage.push({
            protocol: 'ari-auth',
            offset: valOff,
            length: valLen,
            status: 'redacted',
          })
          issues.push('ari-api-key-masked')
        } else if (key === 'endpoint' || key === 'channelid' || key === 'bridgeid' || key === 'app') {
          mapAsciiIdentity(
            buffer,
            valOff,
            valLen,
            'opaque-id',
            collector,
            mapping,
            intents,
            packetIndex,
            'ari',
            'ari-q:',
          )
          coverage.push({
            protocol: 'ari-id',
            offset: valOff,
            length: valLen,
            status: 'covered',
          })
        }
      }
    }
    pos = amp + 1
  }
}

/** Map/mask well-known ARI JSON string values by preceding key name. */
function sanitizeAriJsonStrings(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  const text = decodeAscii(buffer, offset, length)
  // "key"\s*:\s*"value"
  const re = /"(number|name|caller|connected|id|channel|bridge|endpoint|accountcode|language|format|media_uri|target_uri|recording|state)"\s*:\s*"((?:\\.|[^"\\])*)"/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const key = m[1]!.toLowerCase()
    const value = m[2]!
    if (value.length === 0) continue
    // Locate value inside match (after opening quote of value)
    const full = m[0]!
    const valueQuote = full.lastIndexOf(`"${value}"`)
    if (valueQuote < 0) continue
    // value starts one past the quote
    const valueRel = m.index + valueQuote + 1
    const abs = offset + valueRel
    if (key === 'number' || (/^\+?\d{6,}$/.test(value) && (key === 'caller' || key === 'connected'))) {
      mapAsciiIdentity(
        buffer,
        abs,
        value.length,
        'sip-phone',
        collector,
        mapping,
        intents,
        packetIndex,
        'ari',
      )
      coverage.push({ protocol: 'ari-id', offset: abs, length: value.length, status: 'covered' })
    } else if (key === 'name') {
      mapAsciiIdentity(
        buffer,
        abs,
        value.length,
        'person',
        collector,
        mapping,
        intents,
        packetIndex,
        'ari',
      )
      coverage.push({ protocol: 'ari-id', offset: abs, length: value.length, status: 'covered' })
    } else if (key === 'media_uri' || key === 'target_uri' || key === 'recording' || key === 'format') {
      maskBytes(collector, intents, packetIndex, abs, value.length, 'ari-media', 'ari')
      coverage.push({
        protocol: 'ari-body',
        offset: abs,
        length: value.length,
        status: 'redacted',
      })
    } else {
      mapAsciiIdentity(
        buffer,
        abs,
        value.length,
        'opaque-id',
        collector,
        mapping,
        intents,
        packetIndex,
        'ari',
        'ari-json:',
      )
      coverage.push({ protocol: 'ari-id', offset: abs, length: value.length, status: 'covered' })
    }
  }
}
