/**
 * T36 — gRPC length-prefixed messages over HTTP/2 DATA (schema-less).
 * Preserve compressed flag + length; mask message bytes (valid length-delimited opaque).
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { PatchCollector } from './PatchCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import type { AppLayerResult, LayerCoverage } from './types'

export function sanitizeGrpcMessages(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let cursor = offset
  const end = offset + length
  void mapping

  while (cursor + 5 <= end) {
    const compressed = buffer[cursor]!
    const msgLen =
      ((buffer[cursor + 1]! << 24)
        | (buffer[cursor + 2]! << 16)
        | (buffer[cursor + 3]! << 8)
        | buffer[cursor + 4]!) >>> 0
    if (compressed > 1 || cursor + 5 + msgLen > end) {
      maskSpan(buffer, cursor, end - cursor, collector, packetIndex, 'grpc-tail')
      coverage.push({
        protocol: 'grpc',
        offset: cursor,
        length: end - cursor,
        status: 'malformed',
      })
      issues.push('grpc-framing')
      break
    }
    coverage.push({ protocol: 'grpc', offset: cursor, length: 5, status: 'covered' })
    if (msgLen > 0) {
      // Compressed without inverse codec → mask; uncompressed protobuf without schema → mask values
      maskSpan(buffer, cursor + 5, msgLen, collector, packetIndex, 'grpc-msg')
      intents?.recordMaskRange(packetIndex, cursor + 5, msgLen, 'protobuf-schemaless', 'grpc')
      coverage.push({
        protocol: 'grpc-message',
        offset: cursor + 5,
        length: msgLen,
        status: compressed === 1 ? 'unsupported' : 'heuristic',
      })
    }
    cursor += 5 + msgLen
  }

  if (cursor < end) {
    maskSpan(buffer, cursor, end - cursor, collector, packetIndex, 'grpc-pad')
    coverage.push({
      protocol: 'grpc',
      offset: cursor,
      length: end - cursor,
      status: 'heuristic',
    })
  }

  return { coverage, issues: issues.length ? issues : undefined }
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
