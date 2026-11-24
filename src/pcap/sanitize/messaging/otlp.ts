/**
 * T41 — OTLP (gRPC 4317 / HTTP 4318): JSON body via shared path; protobuf without schema → mask.
 * Nested HTTP/gRPC envelope from T36 remains in coverage when those handlers claim first.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { asciiIndexOf, decodeAscii, maskBytes, sanitizeMessageBody } from './common.ts'

function maskOtlpStringValues(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const text = decodeAscii(buffer, offset, length)
  const re = /"stringValue"\s*:\s*"((?:\\.|[^"\\])*)"/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const val = m[1] ?? ''
    if (!val) continue
    const full = m[0]!
    const colon = full.indexOf(':')
    const q1 = full.indexOf('"', colon + 1)
    const valueStart = offset + (m.index ?? 0) + q1 + 1
    maskBytes(collector, intents, packetIndex, valueStart, val.length, 'otlp-string', 'otlp')
  }
}
import { sanitizeGrpcMessages } from '../grpc.ts'

export const OTLP_GRPC_PORT = 4317
export const OTLP_HTTP_PORT = 4318

export function isOtlpPortHint(src: number, dst: number): boolean {
  return (
    src === OTLP_GRPC_PORT
    || dst === OTLP_GRPC_PORT
    || src === OTLP_HTTP_PORT
    || dst === OTLP_HTTP_PORT
  )
}

export function looksLikeOtlp(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 4) return false
  // gRPC length-prefixed message
  if (buffer[offset] === 0x00 && length >= 5) return true
  let i = offset
  const end = offset + length
  while (i < end && (buffer[i] === 0x20 || buffer[i] === 0x09 || buffer[i] === 0x0a)) i++
  if (i < end && (buffer[i] === 0x7b || buffer[i] === 0x5b)) return true
  // HTTP/1 request to OTLP path
  const head = decodeAscii(buffer, offset, Math.min(length, 48))
  return (
    head.startsWith('POST ')
    || head.startsWith('GET ')
    || asciiIndexOf(buffer, offset, Math.min(length, 128), 'opentelemetry') >= 0
  )
}

export function sanitizeOtlp(
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
  if (!isOtlpPortHint(srcPort, dstPort) && !looksLikeOtlp(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []

  // JSON export path
  let i = offset
  const end = offset + length
  while (i < end && (buffer[i] === 0x20 || buffer[i] === 0x09 || buffer[i] === 0x0a || buffer[i] === 0x0d)) {
    i++
  }
  if (i < end && (buffer[i] === 0x7b || buffer[i] === 0x5b)) {
    coverage.push(
      ...sanitizeMessageBody(
        buffer,
        offset,
        length,
        collector,
        mapping,
        intents,
        packetIndex,
        'otlp',
        highPrivacy,
      ),
    )
    // Resource/log string attributes and bodies — fail-closed without pinned OTLP schema
    maskOtlpStringValues(buffer, offset, length, collector, intents, packetIndex)
    issues.push('otlp-json-schema-baseline')
    return { coverage, issues }
  }

  // gRPC framed protobuf — reuse T36 walker (schemaless → mask values)
  if (buffer[offset] === 0x00 && length >= 5) {
    const g = sanitizeGrpcMessages(
      buffer,
      offset,
      length,
      collector,
      mapping,
      intents,
      packetIndex,
    )
    for (const c of g.coverage) {
      coverage.push({
        protocol: c.protocol.startsWith('grpc') ? 'otlp-protobuf' : c.protocol,
        offset: c.offset,
        length: c.length,
        status: c.status,
      })
    }
    if (g.issues) for (const issue of g.issues) issues.push(issue)
    issues.push('otlp-protobuf-schemaless-mask')
    return { coverage, issues }
  }

  // HTTP request line / headers carrying OTLP — mask body after headers if present
  const head = decodeAscii(buffer, offset, Math.min(length, 16))
  if (head.startsWith('POST ') || head.startsWith('GET ')) {
    const sep = asciiIndexOf(buffer, offset, length, '\r\n\r\n')
    if (sep >= 0) {
      const hdrLen = sep - offset + 4
      coverage.push({ protocol: 'otlp', offset, length: hdrLen, status: 'covered' })
      const bodyOff = sep + 4
      const bodyLen = end - bodyOff
      if (bodyLen > 0) {
        coverage.push(
          ...sanitizeMessageBody(
            buffer,
            bodyOff,
            bodyLen,
            collector,
            mapping,
            intents,
            packetIndex,
            'otlp',
            highPrivacy,
          ),
        )
      }
      return { coverage, issues }
    }
  }

  maskBytes(collector, intents, packetIndex, offset, length, 'otlp-body', 'otlp')
  coverage.push({ protocol: 'otlp-body', offset, length, status: 'redacted' })
  issues.push('otlp-opaque-masked')
  return { coverage, issues }
}
