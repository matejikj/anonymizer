/**
 * T30 — CoAP (UDP 5683): header/code/MID preserve; token map; Uri-* options; payload JSON/mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import type { ApplicationFlowEndpoint } from '../applicationDispatchTypes.ts'
import {
  mapAsciiIdentity,
  maskBytes,
  readU16be,
  sanitizePayloadBody,
  sanitizeSlashPath,
} from './common.ts'
import {
  type CoapBlock2Session,
  coapBlock2ExchangeKey,
  parseCoapBlockOption,
  uriPathFingerprintFromOptions,
} from './coapBlock2Session.ts'

export const COAP_UDP_PORT = 5683

export function isCoapPortHint(src: number, dst: number): boolean {
  return src === COAP_UDP_PORT || dst === COAP_UDP_PORT
}

export function looksLikeCoap(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 4) return false
  const ver = (buffer[offset]! >> 6) & 0x03
  return ver === 1
}

export interface SanitizeCoapContext {
  readonly flowEndpoint?: ApplicationFlowEndpoint | null
  readonly coapBlock2?: CoapBlock2Session
}

export function sanitizeCoap(
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
  ctx: SanitizeCoapContext = {},
): AppLayerResult | null {
  if (!isCoapPortHint(srcPort, dstPort) && !looksLikeCoap(buffer, offset, length)) return null
  if (length < 4 || !looksLikeCoap(buffer, offset, length)) {
    if (isCoapPortHint(srcPort, dstPort)) {
      maskBytes(collector, intents, packetIndex, offset, length, 'coap-session', 'coap')
      return {
        coverage: [{ protocol: 'coap', offset, length, status: 'redacted' }],
        issues: ['coap-opaque'],
      }
    }
    return null
  }

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const tkl = buffer[offset]! & 0x0f
  coverage.push({ protocol: 'coap', offset, length: 4, status: 'covered' })
  let pos = offset + 4
  const end = offset + length
  const tokenBytes = new Uint8Array(tkl)
  const uriPathParts: Uint8Array[] = []
  let block2:
    | {
        blockNum: number
        more: boolean
        optionOffset: number
        optionLength: number
      }
    | undefined

  if (tkl > 0) {
    if (pos + tkl > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'coap-token', 'coap')
      return { coverage, issues: ['coap-token-truncated'] }
    }
    tokenBytes.set(buffer.subarray(pos, pos + tkl))
    mapAsciiIdentity(
      buffer,
      pos,
      tkl,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'coap',
    )
    coverage.push({ protocol: 'coap-token', offset: pos, length: tkl, status: 'covered' })
    pos += tkl
  }

  // Options until 0xFF payload marker
  let optNum = 0
  while (pos < end) {
    const b = buffer[pos]!
    if (b === 0xff) {
      pos++
      break
    }
    const deltaNib = (b >> 4) & 0x0f
    const lenNib = b & 0x0f
    pos++
    let delta = deltaNib
    let optLen = lenNib
    if (deltaNib === 13) {
      if (pos >= end) break
      delta = buffer[pos]! + 13
      pos++
    } else if (deltaNib === 14) {
      if (pos + 1 >= end) break
      delta = readU16be(buffer, pos) + 269
      pos += 2
    } else if (deltaNib === 15) {
      issues.push('coap-reserved-delta')
      break
    }
    if (lenNib === 13) {
      if (pos >= end) break
      optLen = buffer[pos]! + 13
      pos++
    } else if (lenNib === 14) {
      if (pos + 1 >= end) break
      optLen = readU16be(buffer, pos) + 269
      pos += 2
    } else if (lenNib === 15) {
      issues.push('coap-reserved-len')
      break
    }
    optNum += delta
    if (pos + optLen > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'coap-option', 'coap')
      break
    }
    if (optNum === 11 && optLen > 0) {
      uriPathParts.push(buffer.subarray(pos, pos + optLen))
    }
    if (optNum === 23) {
      const parsed = parseCoapBlockOption(buffer.subarray(pos, pos + optLen))
      if (parsed) {
        block2 = {
          blockNum: parsed.blockNum,
          more: parsed.more,
          optionOffset: pos,
          optionLength: optLen,
        }
      }
    }
    sanitizeOption(
      buffer,
      pos,
      optLen,
      optNum,
      collector,
      mapping,
      intents,
      packetIndex,
      highPrivacy,
      coverage,
      issues,
      block2?.optionOffset === pos,
    )
    pos += optLen
  }

  if (pos < end) {
    const payloadLen = end - pos
    const multiBlockPayload =
      block2 !== undefined && (block2.more || block2.blockNum > 0)
    if (multiBlockPayload) {
      issues.push('coap-block2-pending')
    }
    const payloadCoverage = sanitizePayloadBody(
      buffer,
      pos,
      payloadLen,
      collector,
      mapping,
      intents,
      packetIndex,
      'coap',
      highPrivacy,
    )
    if (multiBlockPayload) {
      for (const span of payloadCoverage) {
        coverage.push({ ...span, status: 'requires-reassembly' })
      }
    } else {
      coverage.push(...payloadCoverage)
    }

    if (block2 && ctx.coapBlock2) {
      const exchangeKey = coapBlock2ExchangeKey({
        srcIp: ctx.flowEndpoint?.srcIp,
        dstIp: ctx.flowEndpoint?.dstIp,
        srcPort,
        dstPort,
        token: tokenBytes,
        uriPathFingerprint: uriPathFingerprintFromOptions(uriPathParts),
      })
      ctx.coapBlock2.recordSegment(exchangeKey, {
        packetIndex,
        blockNum: block2.blockNum,
        more: block2.more,
        payloadOffset: pos,
        payloadLength: payloadLen,
        blockOptionOffset: block2.optionOffset,
        blockOptionLength: block2.optionLength,
      })
    }
  }

  return { coverage, issues }
}

function sanitizeOption(
  buffer: Uint8Array,
  offset: number,
  length: number,
  optNum: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  coverage: AppLayerResult['coverage'],
  issues: string[],
  isBlock2Option: boolean,
): void {
  // 3 Uri-Host, 11 Uri-Path, 15 Uri-Query, 35 Proxy-Uri, 39 Proxy-Scheme
  if (optNum === 3) {
    mapAsciiIdentity(
      buffer,
      offset,
      length,
      'hostname',
      collector,
      mapping,
      intents,
      packetIndex,
      'coap',
    )
    coverage.push({ protocol: 'coap-uri', offset, length, status: 'covered' })
    return
  }
  if (optNum === 11 || optNum === 15) {
    coverage.push(
      ...sanitizeSlashPath(
        buffer,
        offset,
        length,
        collector,
        mapping,
        intents,
        packetIndex,
        'coap',
        highPrivacy,
      ),
    )
    return
  }
  if (optNum === 35 || optNum === 39) {
    maskBytes(collector, intents, packetIndex, offset, length, 'coap-proxy', 'coap')
    coverage.push({ protocol: 'coap-uri', offset, length, status: 'redacted' })
    return
  }
  if (optNum === 6) {
    coverage.push({ protocol: 'coap', offset, length, status: 'covered' })
    return
  }
  if (optNum === 23) {
    if (isBlock2Option) {
      coverage.push({ protocol: 'coap-block2', offset, length, status: 'covered' })
    } else {
      coverage.push({ protocol: 'coap', offset, length, status: 'covered' })
    }
    return
  }
  if (optNum === 27) {
    coverage.push({ protocol: 'coap-block1', offset, length, status: 'covered' })
    issues.push('coap-block1-segment')
    return
  }
  if (optNum === 7 || optNum === 12 /* Content-Format */ || optNum === 14 || optNum === 17) {
    coverage.push({ protocol: 'coap', offset, length, status: 'covered' })
    return
  }
  maskBytes(collector, intents, packetIndex, offset, length, 'coap-option', 'coap')
  coverage.push({ protocol: 'coap-body', offset, length, status: 'redacted' })
}
