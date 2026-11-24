/**
 * T36 — WebSocket (RFC 6455) frame walker: XOR-unmask → child sanitize → remask.
 * permessage-deflate and unknown binary → fail-closed mask.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import { PatchCollector } from './PatchCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import { maskRangeDeferredProtocolNeutral } from './deferredMaskMeta.ts'
import { sanitizeSipMessage } from './sip'
import { classifySipPayload } from '../protocols/application/sip/classify'
import { sanitizeHttpBody } from './httpBody'
import { FingerprintSession } from '../anonymization/fingerprintSession'
import type { AppLayerResult, LayerCoverage } from './types'

const OP_CONTINUATION = 0x0
const OP_TEXT = 0x1
const OP_BINARY = 0x2
const OP_CLOSE = 0x8
const OP_PING = 0x9
const OP_PONG = 0xa

export type WebSocketSubprotocol = 'sip' | 'json' | 'unknown'

export function looksLikeWebSocketFrame(
  data: Uint8Array,
  offset: number,
  length: number,
): boolean {
  if (length < 2) return false
  const b0 = data[offset]!
  const b1 = data[offset + 1]!
  const rsv = (b0 >> 4) & 0x07
  if (rsv !== 0) return false // permessage-deflate needs prior negotiation
  const opcode = b0 & 0x0f
  // Do not claim stream start on continuation alone (avoids TACACS/Diameter false positives)
  if (
    opcode !== OP_TEXT
    && opcode !== OP_BINARY
    && opcode !== OP_CLOSE
    && opcode !== OP_PING
    && opcode !== OP_PONG
  ) {
    return false
  }
  const masked = (b1 & 0x80) !== 0
  const len7 = b1 & 0x7f
  // Mid-stream content probe: require client masking (server frames need HTTP upgrade path)
  if (!masked) return false
  if ((opcode === OP_CLOSE || opcode === OP_PING || opcode === OP_PONG) && len7 > 125) {
    return false
  }
  let hdr = 2
  if (len7 === 126) hdr += 2
  else if (len7 === 127) hdr += 8
  hdr += 4 // mask key
  if (length < hdr) return false
  let payloadLen = len7
  if (len7 === 126) {
    payloadLen = ((data[offset + 2]! << 8) | data[offset + 3]!) >>> 0
  } else if (len7 === 127) {
    if (
      data[offset + 2] !== 0
      || data[offset + 3] !== 0
      || data[offset + 4] !== 0
      || data[offset + 5] !== 0
    ) {
      return false
    }
    payloadLen =
      ((data[offset + 6]! << 24)
        | (data[offset + 7]! << 16)
        | (data[offset + 8]! << 8)
        | data[offset + 9]!) >>> 0
  }
  // Prefer exact message framing for content-sniff claim
  return hdr + payloadLen === length || (hdr + payloadLen < length && hdr + payloadLen >= 8)
}

export function sanitizeWebSocket(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  options: {
    readonly subprotocol?: WebSocketSubprotocol
    readonly mediaFlowIndex?: MediaFlowIndex
    readonly compressed?: boolean
    readonly highPrivacy?: boolean
  } = {},
): AppLayerResult | null {
  if (!looksLikeWebSocketFrame(buffer, offset, length) && length < 2) return null

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const sub = options.subprotocol ?? 'unknown'

  if (options.compressed) {
    maskSpan(buffer, offset, length, collector, packetIndex, 'ws-deflate')
    coverage.push({ protocol: 'websocket', offset, length, status: 'unsupported' })
    return { coverage, issues: ['ws-permessage-deflate'] }
  }

  let cursor = offset
  const end = offset + length
  let claimed = false
  /** Assembled text message across continuations (logical, unmasked). */
  let assemble: Uint8Array | null = null
  let assembleWireSpans: { wireOff: number; mask: Uint8Array | null; len: number }[] = []

  while (cursor + 2 <= end) {
    if (!looksLikeWebSocketFrame(buffer, cursor, end - cursor)) break
    const parsed = parseFrame(buffer, cursor, end - cursor)
    if (!parsed) break
    claimed = true
    coverage.push({
      protocol: 'websocket',
      offset: parsed.headerOff,
      length: parsed.headerLen,
      status: 'covered',
    })

    const { opcode, fin, masked, maskKey, payloadOff, payloadLen, frameLen } = parsed

    if (opcode === OP_CLOSE || opcode === OP_PING || opcode === OP_PONG) {
      // Control payload may carry UTF-8 reason — mask body, keep framing
      if (payloadLen > 0) {
        if (masked && maskKey) {
          sanitizeMaskedPayload(
            buffer,
            payloadOff,
            payloadLen,
            maskKey,
            collector,
            mapping,
            intents,
            packetIndex,
            'mask',
            options,
          )
        } else {
          maskSpan(buffer, payloadOff, payloadLen, collector, packetIndex, 'ws-control')
        }
        coverage.push({
          protocol: 'websocket-control',
          offset: payloadOff,
          length: payloadLen,
          status: 'covered',
        })
      }
      cursor += frameLen
      continue
    }

    if (opcode === OP_BINARY) {
      if (masked && maskKey) {
        sanitizeMaskedPayload(
          buffer,
          payloadOff,
          payloadLen,
          maskKey,
          collector,
          mapping,
          intents,
          packetIndex,
          'mask',
          options,
        )
      } else {
        maskSpan(buffer, payloadOff, payloadLen, collector, packetIndex, 'ws-bin')
      }
      // T63 — binary payload masked → redacted.
      coverage.push({
        protocol: 'websocket-payload',
        offset: payloadOff,
        length: payloadLen,
        status: 'redacted',
      })
      cursor += frameLen
      continue
    }

    if (opcode === OP_TEXT || opcode === OP_CONTINUATION) {
      const logical = extractLogical(buffer, payloadOff, payloadLen, masked ? maskKey : null)
      if (opcode === OP_TEXT) {
        assemble = logical
        assembleWireSpans = [{
          wireOff: payloadOff,
          mask: masked ? maskKey : null,
          len: payloadLen,
        }]
      } else if (assemble) {
        const merged: Uint8Array = new Uint8Array(assemble.length + logical.length)
        merged.set(assemble)
        merged.set(logical, assemble.length)
        assemble = merged
        assembleWireSpans.push({
          wireOff: payloadOff,
          mask: masked ? maskKey : null,
          len: payloadLen,
        })
      }

      if (fin && assemble) {
        const child = sanitizeLogicalMessage(
          assemble,
          assembleWireSpans,
          buffer,
          collector,
          mapping,
          intents,
          packetIndex,
          sub,
          options,
          issues,
        )
        coverage.push(...child)
        assemble = null
        assembleWireSpans = []
      }
      cursor += frameLen
      continue
    }

    // Reserved opcode — mask payload
    if (payloadLen > 0) {
      maskSpan(buffer, payloadOff, payloadLen, collector, packetIndex, 'ws-opcode')
    }
    coverage.push({
      protocol: 'websocket-payload',
      offset: payloadOff,
      length: payloadLen,
      status: 'unsupported',
    })
    cursor += frameLen
  }

  if (!claimed) return null
  if (cursor < end) {
    // Trailing incomplete frame
    coverage.push({
      protocol: 'websocket',
      offset: cursor,
      length: end - cursor,
      status: 'requires-reassembly',
    })
  }
  return { coverage, issues: issues.length ? issues : undefined }
}

interface ParsedFrame {
  readonly headerOff: number
  readonly headerLen: number
  readonly frameLen: number
  readonly opcode: number
  readonly fin: boolean
  readonly masked: boolean
  readonly maskKey: Uint8Array | null
  readonly payloadOff: number
  readonly payloadLen: number
}

function parseFrame(buffer: Uint8Array, offset: number, length: number): ParsedFrame | null {
  if (length < 2) return null
  const b0 = buffer[offset]!
  const b1 = buffer[offset + 1]!
  const fin = (b0 & 0x80) !== 0
  const opcode = b0 & 0x0f
  const masked = (b1 & 0x80) !== 0
  const len7 = b1 & 0x7f
  let hdr = 2
  let payloadLen = len7
  if (len7 === 126) {
    if (length < 4) return null
    payloadLen = ((buffer[offset + 2]! << 8) | buffer[offset + 3]!) >>> 0
    hdr = 4
  } else if (len7 === 127) {
    if (length < 10) return null
    if (
      buffer[offset + 2] !== 0
      || buffer[offset + 3] !== 0
      || buffer[offset + 4] !== 0
      || buffer[offset + 5] !== 0
    ) {
      return null
    }
    payloadLen =
      ((buffer[offset + 6]! << 24)
        | (buffer[offset + 7]! << 16)
        | (buffer[offset + 8]! << 8)
        | buffer[offset + 9]!) >>> 0
    hdr = 10
  }
  let maskKey: Uint8Array | null = null
  if (masked) {
    if (length < hdr + 4) return null
    maskKey = buffer.slice(offset + hdr, offset + hdr + 4)
    hdr += 4
  }
  if (length < hdr + payloadLen) return null
  return {
    headerOff: offset,
    headerLen: hdr,
    frameLen: hdr + payloadLen,
    opcode,
    fin,
    masked,
    maskKey,
    payloadOff: offset + hdr,
    payloadLen,
  }
}

function extractLogical(
  buffer: Uint8Array,
  payloadOff: number,
  payloadLen: number,
  maskKey: Uint8Array | null,
): Uint8Array {
  const out = buffer.slice(payloadOff, payloadOff + payloadLen)
  if (maskKey) {
    for (let i = 0; i < out.length; i++) {
      out[i] = out[i]! ^ maskKey[i & 3]!
    }
  }
  return out
}

function sanitizeLogicalMessage(
  logical: Uint8Array,
  spans: { wireOff: number; mask: Uint8Array | null; len: number }[],
  wire: Uint8Array,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  sub: WebSocketSubprotocol,
  options: {
    readonly mediaFlowIndex?: MediaFlowIndex
    readonly highPrivacy?: boolean
  },
  issues: string[],
): LayerCoverage[] {
  const coverage: LayerCoverage[] = []
  const local = new PatchCollector(logical.length)
  void intents // nested logical offsets ≠ wire; discovery uses SIP/HTTP paths on direct captures

  let kind: 'sip' | 'json' | 'mask' = 'mask'
  if (sub === 'sip' || looksLikeSipText(logical)) kind = 'sip'
  else if (sub === 'json' || looksLikeJson(logical)) kind = 'json'

  if (kind === 'sip') {
    const classification = classifySipPayload(logical, 0, logical.length, { portHint: true })
    if (classification.kind === 'complete') {
      options.mediaFlowIndex?.registerFromSipMessage(classification.message, logical)
      const sipIssues = sanitizeSipMessage(logical, classification.message, 'tcp', local, mapping)
      if (sipIssues.length) issues.push(...sipIssues)
      coverage.push({
        protocol: 'websocket-payload',
        offset: spans[0]!.wireOff,
        length: spans.reduce((n, s) => n + s.len, 0),
        status: 'covered',
      })
      coverage.push({
        protocol: 'sip',
        offset: spans[0]!.wireOff,
        length: spans.reduce((n, s) => n + s.len, 0),
        status: 'covered',
      })
    } else {
      maskLogical(local, 0, logical.length, packetIndex, 'ws-sip-incomplete')
      coverage.push({
        protocol: 'websocket-payload',
        offset: spans[0]!.wireOff,
        length: spans.reduce((n, s) => n + s.len, 0),
        status: 'malformed',
      })
      issues.push('ws-sip-incomplete')
    }
  } else if (kind === 'json') {
    const body = sanitizeHttpBody({
      buffer: logical,
      bodyAbsOffset: 0,
      bodyLength: logical.length,
      headers: { contentType: 'application/json', contentEncoding: null, transferEncoding: null },
      collector: local,
      mapping,
      intents: undefined,
      packetIndex,
      highPrivacy: options.highPrivacy ?? false,
    })
    coverage.push({
      protocol: 'websocket-payload',
      offset: spans[0]!.wireOff,
      length: spans.reduce((n, s) => n + s.len, 0),
      status: body.coverageStatus,
    })
  } else {
    maskLogical(local, 0, logical.length, packetIndex, 'ws-text')
    // T63 — unknown text masked → redacted (until T69).
    coverage.push({
      protocol: 'websocket-payload',
      offset: spans[0]!.wireOff,
      length: spans.reduce((n, s) => n + s.len, 0),
      status: 'redacted',
    })
  }

  local.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
  const patched = logical.slice()
  for (const p of local.getPatches()) patched.set(p.data, p.offset)
  projectRemasked(patched, spans, wire, collector)
  void wire
  return coverage
}

function sanitizeMaskedPayload(
  buffer: Uint8Array,
  payloadOff: number,
  payloadLen: number,
  maskKey: Uint8Array,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  mode: 'mask',
  _options: object,
): void {
  void mapping
  void intents
  void mode
  // Control/binary: remask after neutral fill of logical
  collector.addDeferred(payloadOff, payloadLen, () => {
    const fill = createProtocolNeutralMaskFill({
      length: payloadLen,
      packetIndex,
      offset: payloadOff,
      domain: 'ws-payload',
    })
    const out = new Uint8Array(payloadLen)
    for (let i = 0; i < payloadLen; i++) {
      out[i] = fill[i]! ^ maskKey[i & 3]!
    }
    return out
  }, { fallbackKind: 'binary-mask', protocol: 'websocket', packetIndex })
  void buffer
}

function projectRemasked(
  patchedLogical: Uint8Array,
  spans: { wireOff: number; mask: Uint8Array | null; len: number }[],
  _wire: Uint8Array,
  collector: PatchCollector,
): void {
  let logicalOff = 0
  for (const span of spans) {
    const slice = patchedLogical.subarray(logicalOff, logicalOff + span.len)
    const out = new Uint8Array(span.len)
    for (let i = 0; i < span.len; i++) {
      const plain = slice[i]!
      out[i] = span.mask ? plain ^ span.mask[i & 3]! : plain
    }
    try {
      collector.add(span.wireOff, out)
    } catch {
      collector.maskRange(span.wireOff, out)
    }
    logicalOff += span.len
  }
}

function maskLogical(
  collector: PatchCollector,
  off: number,
  len: number,
  packetIndex: number,
  domain: string,
): void {
  if (len <= 0) return
  maskRangeDeferredProtocolNeutral(collector, off, len, packetIndex, domain, 'websocket', domain)
}

function maskSpan(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  packetIndex: number,
  domain: string,
): void {
  if (len <= 0) return
  try {
    maskRangeDeferredProtocolNeutral(
      collector,
      abs,
      len,
      packetIndex,
      domain,
      'websocket',
      domain,
    )
  } catch {
    /* overlap */
  }
  void buffer
}

function looksLikeSipText(data: Uint8Array): boolean {
  const head = new TextDecoder('ascii', { fatal: false }).decode(data.subarray(0, Math.min(16, data.length)))
  return /^(?:INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER|SUBSCRIBE|NOTIFY|INFO|MESSAGE|REFER|UPDATE|PRACK|PUBLISH|SIP\/2\.0)/i.test(
    head,
  )
}

function looksLikeJson(data: Uint8Array): boolean {
  if (data.length === 0) return false
  const c = data[0]!
  return c === 0x7b || c === 0x5b // { or [
}
