/**
 * T36 — HTTP/2 cleartext (h2c): preface + 9-byte frame walker.
 * HEADERS/CONTINUATION/PUSH_PROMISE payloads fail-closed mask (no length-preserving HPACK rewrite).
 * DATA → optional gRPC walker or body mask.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { PatchCollector } from './PatchCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import { sanitizeGrpcMessages } from './grpc'
import { looksLikeSbiJsonBody, sanitizeSbiJsonBody } from './sbi5g'
import type { AppLayerResult, LayerCoverage } from './types'

const PREFACE = new TextEncoder().encode('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n')

const FRAME_DATA = 0x0
const FRAME_HEADERS = 0x1
const FRAME_PRIORITY = 0x2
const FRAME_RST_STREAM = 0x3
const FRAME_SETTINGS = 0x4
const FRAME_PUSH_PROMISE = 0x5
const FRAME_PING = 0x6
const FRAME_GOAWAY = 0x7
const FRAME_WINDOW_UPDATE = 0x8
const FRAME_CONTINUATION = 0x9

export function looksLikeHttp2Preface(data: Uint8Array, offset: number, length: number): boolean {
  if (length < PREFACE.length) return false
  for (let i = 0; i < PREFACE.length; i++) {
    if (data[offset + i] !== PREFACE[i]) return false
  }
  return true
}

/** Strong frame claim: SETTINGS on stream 0 (typical first frame after preface). */
export function looksLikeHttp2Frame(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 9) return false
  const plen = ((data[offset]! << 16) | (data[offset + 1]! << 8) | data[offset + 2]!) >>> 0
  const type = data[offset + 3]!
  const stream =
    (((data[offset + 5]! & 0x7f) << 24)
      | (data[offset + 6]! << 16)
      | (data[offset + 7]! << 8)
      | data[offset + 8]!) >>> 0
  if (type !== FRAME_SETTINGS || stream !== 0) return false
  if (plen > 256) return false // SETTINGS payloads are small
  return 9 + plen <= length
}

export function sanitizeHttp2(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  options: { readonly preferGrpc?: boolean } = {},
): AppLayerResult | null {
  let cursor = offset
  const end = offset + length
  const coverage: LayerCoverage[] = []
  const issues: string[] = []

  if (looksLikeHttp2Preface(buffer, cursor, end - cursor)) {
    coverage.push({
      protocol: 'http2',
      offset: cursor,
      length: PREFACE.length,
      status: 'covered',
    })
    cursor += PREFACE.length
  } else if (!looksLikeHttp2Frame(buffer, cursor, end - cursor)) {
    return null
  }

  let claimed = coverage.length > 0

  while (cursor + 9 <= end) {
    const plen = ((buffer[cursor]! << 16) | (buffer[cursor + 1]! << 8) | buffer[cursor + 2]!) >>> 0
    const type = buffer[cursor + 3]!
    const flags = buffer[cursor + 4]!
    if (cursor + 9 + plen > end) {
      coverage.push({
        protocol: 'http2',
        offset: cursor,
        length: end - cursor,
        status: 'requires-reassembly',
      })
      issues.push('http2-truncated-frame')
      break
    }
    claimed = true
    coverage.push({ protocol: 'http2', offset: cursor, length: 9, status: 'covered' })
    const payloadOff = cursor + 9

    switch (type) {
      case FRAME_SETTINGS:
      case FRAME_PING:
      case FRAME_WINDOW_UPDATE:
      case FRAME_PRIORITY:
      case FRAME_RST_STREAM:
        // Structural — preserve
        coverage.push({
          protocol: 'http2-frame',
          offset: payloadOff,
          length: plen,
          status: 'covered',
        })
        break
      case FRAME_GOAWAY:
        // Last-stream / error code preserve; opaque debug data mask
        if (plen > 8) {
          maskSpan(buffer, payloadOff + 8, plen - 8, collector, packetIndex, 'http2-goaway')
        }
        coverage.push({
          protocol: 'http2-frame',
          offset: payloadOff,
          length: plen,
          status: 'covered',
        })
        break
      case FRAME_HEADERS:
      case FRAME_CONTINUATION:
      case FRAME_PUSH_PROMISE: {
        // Fail-closed: no same-length HPACK rewrite → mask header block
        let bodyOff = payloadOff
        let bodyLen = plen
        if (type === FRAME_HEADERS || type === FRAME_PUSH_PROMISE) {
          const padded = (flags & 0x08) !== 0
          const priority = type === FRAME_HEADERS && (flags & 0x20) !== 0
          if (type === FRAME_PUSH_PROMISE) {
            bodyOff += 4 // promised stream id
            bodyLen -= 4
          }
          if (priority && bodyLen >= 5) {
            bodyOff += 5
            bodyLen -= 5
          }
          if (padded && bodyLen >= 1) {
            const pad = buffer[payloadOff]!
            bodyOff += 1
            bodyLen -= 1 + pad
          }
        }
        if (bodyLen > 0) {
          maskSpan(buffer, bodyOff, bodyLen, collector, packetIndex, 'http2-hpack')
          intents?.recordMaskRange(packetIndex, bodyOff, bodyLen, 'hpack-no-rewrite', 'http2')
        }
        coverage.push({
          protocol: 'http2-headers',
          offset: payloadOff,
          length: plen,
          status: 'heuristic',
        })
        issues.push('http2-hpack-masked')
        break
      }
      case FRAME_DATA: {
        let dataOff = payloadOff
        let dataLen = plen
        if ((flags & 0x08) !== 0 && dataLen >= 1) {
          const pad = buffer[payloadOff]!
          dataOff += 1
          dataLen -= 1 + pad
        }
        if (dataLen > 0) {
          if (looksLikeSbiJsonBody(buffer, dataOff, dataLen)) {
            // T61 — schema-aware SBI JSON in DATA (HPACK path/API select unavailable)
            const sbi = sanitizeSbiJsonBody(
              buffer,
              dataOff,
              dataLen,
              collector,
              mapping,
              intents,
              packetIndex,
            )
            coverage.push(...sbi.coverage)
            if (sbi.issues) issues.push(...sbi.issues)
          } else if (options.preferGrpc || looksLikeGrpc(buffer, dataOff, dataLen)) {
            const g = sanitizeGrpcMessages(
              buffer,
              dataOff,
              dataLen,
              collector,
              mapping,
              intents,
              packetIndex,
            )
            coverage.push(...g.coverage)
            if (g.issues) issues.push(...g.issues)
          } else {
            maskSpan(buffer, dataOff, dataLen, collector, packetIndex, 'http2-data')
            coverage.push({
              protocol: 'http2-data',
              offset: dataOff,
              length: dataLen,
              status: 'heuristic',
            })
          }
        }
        break
      }
      default:
        if (plen > 0) {
          maskSpan(buffer, payloadOff, plen, collector, packetIndex, `http2-t${type}`)
        }
        coverage.push({
          protocol: 'http2-frame',
          offset: payloadOff,
          length: plen,
          status: 'unsupported',
        })
        break
    }
    cursor += 9 + plen
  }

  if (!claimed) return null
  return { coverage, issues: issues.length ? issues : undefined }
}

function looksLikeGrpc(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 5) return false
  const compressed = buffer[offset]!
  if (compressed > 1) return false
  const msgLen =
    ((buffer[offset + 1]! << 24)
      | (buffer[offset + 2]! << 16)
      | (buffer[offset + 3]! << 8)
      | buffer[offset + 4]!) >>> 0
  return 5 + msgLen <= length
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
    collector.maskRangeDeferred(abs, len, () =>
      createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain }),
    )
  } catch {
    /* overlap */
  }
  void buffer
}
