/**
 * T29 — MongoDB wire (TCP 27017): OP_MSG header preserve; BSON fail-closed; SASL payload mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { asciiIndexOf, decodeAscii, maskBytes, readU32le } from './common.ts'

export const MONGODB_TCP_PORT = 27_017

const OP_MSG = 2013
const OP_QUERY = 2004
const OP_REPLY = 1
const OP_COMPRESSED = 2012

export function isMongodbPortHint(src: number, dst: number): boolean {
  return src === MONGODB_TCP_PORT || dst === MONGODB_TCP_PORT
}

export function looksLikeMongodb(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 16) return false
  const msgLen = readU32le(buffer, offset)
  const op = readU32le(buffer, offset + 12)
  return (
    msgLen >= 16
    && msgLen <= length + 64
    && msgLen < 0x10_0000
    && (op === OP_MSG || op === OP_QUERY || op === OP_REPLY || op === OP_COMPRESSED)
  )
}

export function sanitizeMongodb(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  _highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isMongodbPortHint(srcPort, dstPort) && !looksLikeMongodb(buffer, offset, length)) {
    return null
  }

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos + 16 <= end) {
    const msgLen = readU32le(buffer, pos)
    if (msgLen < 16 || pos + msgLen > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'mongo-desync', 'mongodb')
      coverage.push({
        protocol: 'mongodb-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('mongodb-frame-desync')
      break
    }
    const opcode = readU32le(buffer, pos + 12)
    coverage.push({ protocol: 'mongodb', offset: pos, length: 16, status: 'covered' })
    const bodyOff = pos + 16
    const bodyLen = msgLen - 16

    if (opcode === OP_COMPRESSED) {
      maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'mongo-compressed', 'mongodb')
      coverage.push({
        protocol: 'mongodb-body',
        offset: bodyOff,
        length: bodyLen,
        status: 'redacted',
      })
      issues.push('mongodb-compressed-masked')
    } else if (opcode === OP_MSG) {
      // flags(4) + sections
      if (bodyLen >= 4) {
        coverage.push({ protocol: 'mongodb', offset: bodyOff, length: 4, status: 'covered' })
        sanitizeOpMsgSections(
          buffer,
          bodyOff + 4,
          bodyLen - 4,
          collector,
          intents,
          packetIndex,
          coverage,
          issues,
        )
      }
    } else {
      // OP_QUERY / OP_REPLY — mask BSON body fail-closed
      maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'mongo-bson', 'mongodb')
      coverage.push({
        protocol: 'mongodb-body',
        offset: bodyOff,
        length: bodyLen,
        status: 'redacted',
      })
    }

    pos += msgLen
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'mongo-session', 'mongodb')
    coverage.push({ protocol: 'mongodb', offset, length, status: 'redacted' })
  }

  void mapping
  return { coverage, issues }
}

function sanitizeOpMsgSections(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  let pos = offset
  const end = offset + length
  while (pos < end) {
    const kind = buffer[pos]!
    pos++
    if (kind === 0) {
      // Body BSON document
      if (pos + 4 > end) break
      const docLen = readU32le(buffer, pos)
      if (docLen < 5 || pos + docLen > end) {
        maskBytes(collector, intents, packetIndex, pos - 1, end - (pos - 1), 'mongo-bson', 'mongodb')
        coverage.push({
          protocol: 'mongodb-body',
          offset: pos - 1,
          length: end - (pos - 1),
          status: 'redacted',
        })
        break
      }
      sanitizeBsonDocument(
        buffer,
        pos,
        docLen,
        collector,
        intents,
        packetIndex,
        coverage,
        issues,
      )
      pos += docLen
    } else if (kind === 1) {
      // Document sequence: size + identifier cstring + docs
      if (pos + 4 > end) break
      const seqSize = readU32le(buffer, pos)
      if (seqSize < 4 || pos + seqSize > end) {
        maskBytes(collector, intents, packetIndex, pos - 1, end - (pos - 1), 'mongo-seq', 'mongodb')
        break
      }
      maskBytes(collector, intents, packetIndex, pos, seqSize, 'mongo-seq', 'mongodb')
      coverage.push({
        protocol: 'mongodb-body',
        offset: pos,
        length: seqSize,
        status: 'redacted',
      })
      pos += seqSize
    } else {
      maskBytes(collector, intents, packetIndex, pos - 1, end - (pos - 1), 'mongo-section', 'mongodb')
      coverage.push({
        protocol: 'mongodb-body',
        offset: pos - 1,
        length: end - (pos - 1),
        status: 'redacted',
      })
      break
    }
  }
}

function sanitizeBsonDocument(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  // Preserve document length; walk elements — known structural keys keep type/name, values mask.
  // Without full schema, fail-closed: mask entire document payload after length prefix,
  // except detect saslStart/saslContinue for explicit auth issue tag.
  coverage.push({ protocol: 'mongodb', offset, length: 4, status: 'covered' })
  const payloadOff = offset + 4
  const payloadLen = length - 5 // exclude trailing NUL
  if (payloadLen <= 0) return

  const text = decodeAscii(buffer, payloadOff, Math.min(payloadLen, 256))
  if (text.includes('saslStart') || text.includes('saslContinue') || text.includes('authenticate')) {
    issues.push('mongodb-sasl-masked')
    coverage.push({
      protocol: 'mongodb-auth',
      offset: payloadOff,
      length: length - 4,
      status: 'redacted',
    })
  } else {
    coverage.push({
      protocol: 'mongodb-body',
      offset: payloadOff,
      length: length - 4,
      status: 'redacted',
    })
  }
  maskBytes(collector, intents, packetIndex, payloadOff, length - 4, 'mongo-bson', 'mongodb')

  // Optionally map db/collection if present as ASCII cstring after known command key
  const dbKey = asciiIndexOf(buffer, payloadOff, payloadLen, '$db\0')
  void dbKey
}
