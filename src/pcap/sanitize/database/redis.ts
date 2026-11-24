/**
 * T29 — Redis RESP (TCP 6379): command names preserve; AUTH args mask; keys diagnostic map / HP mask; values mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { decodeAscii, mapAsciiIdentity, maskBytes } from './common.ts'

export const REDIS_TCP_PORT = 6379

export function isRedisPortHint(src: number, dst: number): boolean {
  return src === REDIS_TCP_PORT || dst === REDIS_TCP_PORT
}

export function looksLikeRedis(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 3) return false
  const b = buffer[offset]!
  return b === 0x2a || b === 0x24 || b === 0x2b || b === 0x2d || b === 0x3a // * $ + - :
}

export function sanitizeRedis(
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
  if (!isRedisPortHint(srcPort, dstPort) && !looksLikeRedis(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos < end) {
    const b = buffer[pos]!
    if (b === 0x2a) {
      // Array: *N\r\n then N bulk strings
      const lineEnd = findCrlf(buffer, pos, end)
      if (lineEnd < 0) {
        maskBytes(collector, intents, packetIndex, pos, end - pos, 'redis-desync', 'redis')
        coverage.push({
          protocol: 'redis-body',
          offset: pos,
          length: end - pos,
          status: 'redacted',
        })
        break
      }
      coverage.push({
        protocol: 'redis',
        offset: pos,
        length: lineEnd + 2 - pos,
        status: 'covered',
      })
      const n = Number.parseInt(decodeAscii(buffer, pos + 1, lineEnd - (pos + 1)), 10)
      pos = lineEnd + 2
      if (!Number.isFinite(n) || n < 0 || n > 64) {
        maskBytes(collector, intents, packetIndex, pos, end - pos, 'redis-array', 'redis')
        coverage.push({
          protocol: 'redis-body',
          offset: pos,
          length: end - pos,
          status: 'redacted',
        })
        break
      }
      const bulks: Array<{ offset: number; length: number }> = []
      for (let i = 0; i < n; i++) {
        const bulk = readBulk(buffer, pos, end, coverage)
        if (!bulk) {
          maskBytes(collector, intents, packetIndex, pos, end - pos, 'redis-bulk', 'redis')
          coverage.push({
            protocol: 'redis-body',
            offset: pos,
            length: end - pos,
            status: 'redacted',
          })
          pos = end
          break
        }
        bulks.push({ offset: bulk.dataOff, length: bulk.dataLen })
        pos = bulk.next
      }
      if (bulks.length > 0) {
        sanitizeCommand(bulks, buffer, collector, mapping, intents, packetIndex, highPrivacy, coverage, issues)
      }
      continue
    }
    if (b === 0x2b || b === 0x3a) {
      // Simple string / integer — preserve status/counts
      const lineEnd = findCrlf(buffer, pos, end)
      if (lineEnd < 0) {
        maskBytes(collector, intents, packetIndex, pos, end - pos, 'redis-line', 'redis')
        break
      }
      coverage.push({
        protocol: 'redis',
        offset: pos,
        length: lineEnd + 2 - pos,
        status: 'covered',
      })
      pos = lineEnd + 2
      continue
    }
    if (b === 0x2d) {
      // Error: -ERR message — preserve prefix, mask text
      const lineEnd = findCrlf(buffer, pos, end)
      if (lineEnd < 0) {
        maskBytes(collector, intents, packetIndex, pos, end - pos, 'redis-error', 'redis')
        break
      }
      // Keep "-ERR " style first token
      let sp = pos + 1
      while (sp < lineEnd && buffer[sp] !== 0x20) sp++
      coverage.push({ protocol: 'redis', offset: pos, length: sp - pos, status: 'covered' })
      if (sp < lineEnd) {
        maskBytes(collector, intents, packetIndex, sp, lineEnd - sp, 'redis-error', 'redis')
        coverage.push({
          protocol: 'redis-body',
          offset: sp,
          length: lineEnd - sp,
          status: 'redacted',
        })
      }
      pos = lineEnd + 2
      continue
    }
    if (b === 0x24) {
      const bulk = readBulk(buffer, pos, end, coverage)
      if (!bulk) {
        maskBytes(collector, intents, packetIndex, pos, end - pos, 'redis-bulk', 'redis')
        break
      }
      if (bulk.dataLen > 0) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          bulk.dataOff,
          bulk.dataLen,
          'redis-value',
          'redis',
        )
        coverage.push({
          protocol: 'redis-body',
          offset: bulk.dataOff,
          length: bulk.dataLen,
          status: 'redacted',
        })
      }
      pos = bulk.next
      continue
    }
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'redis-unknown', 'redis')
    coverage.push({
      protocol: 'redis-body',
      offset: pos,
      length: end - pos,
      status: 'redacted',
    })
    break
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'redis-session', 'redis')
    coverage.push({ protocol: 'redis', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}

function findCrlf(buffer: Uint8Array, offset: number, end: number): number {
  for (let i = offset; i + 1 < end; i++) {
    if (buffer[i] === 0x0d && buffer[i + 1] === 0x0a) return i
  }
  return -1
}

function readBulk(
  buffer: Uint8Array,
  offset: number,
  end: number,
  coverage: AppLayerResult['coverage'],
): { dataOff: number; dataLen: number; next: number } | null {
  if (offset >= end || buffer[offset] !== 0x24) return null
  const lineEnd = findCrlf(buffer, offset, end)
  if (lineEnd < 0) return null
  coverage.push({
    protocol: 'redis',
    offset,
    length: lineEnd + 2 - offset,
    status: 'covered',
  })
  const n = Number.parseInt(decodeAscii(buffer, offset + 1, lineEnd - (offset + 1)), 10)
  const dataOff = lineEnd + 2
  if (n < 0) {
    // null bulk
    return { dataOff, dataLen: 0, next: dataOff }
  }
  if (!Number.isFinite(n) || dataOff + n + 2 > end) return null
  return { dataOff, dataLen: n, next: dataOff + n + 2 }
}

function sanitizeCommand(
  bulks: Array<{ offset: number; length: number }>,
  buffer: Uint8Array,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  const cmd = decodeAscii(buffer, bulks[0]!.offset, bulks[0]!.length).toUpperCase()
  // Command name — leave as-is (already covered by bulk header path; data is ASCII cmd)
  coverage.push({
    protocol: 'redis',
    offset: bulks[0]!.offset,
    length: bulks[0]!.length,
    status: 'covered',
  })

  if (cmd === 'AUTH') {
    for (let i = 1; i < bulks.length; i++) {
      const b = bulks[i]!
      maskBytes(collector, intents, packetIndex, b.offset, b.length, 'redis-auth', 'redis')
      coverage.push({
        protocol: 'redis-auth',
        offset: b.offset,
        length: b.length,
        status: 'redacted',
      })
    }
    issues.push('redis-auth-masked')
    return
  }

  // Typical: CMD key [value…] — key at [1], values after
  for (let i = 1; i < bulks.length; i++) {
    const b = bulks[i]!
    if (i === 1 && !highPrivacy) {
      mapAsciiIdentity(
        buffer,
        b.offset,
        b.length,
        'opaque-id',
        collector,
        mapping,
        intents,
        packetIndex,
        'redis',
      )
      coverage.push({
        protocol: 'redis-key',
        offset: b.offset,
        length: b.length,
        status: 'covered',
      })
    } else {
      maskBytes(collector, intents, packetIndex, b.offset, b.length, 'redis-value', 'redis')
      coverage.push({
        protocol: 'redis-body',
        offset: b.offset,
        length: b.length,
        status: 'redacted',
      })
    }
  }
}
