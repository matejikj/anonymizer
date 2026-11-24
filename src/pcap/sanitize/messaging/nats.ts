/**
 * T41 — NATS (TCP 4222): CONNECT credentials mask; PUB/MSG subject map + payload JSON/mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { decodeAscii, mapAsciiIdentity, maskBytes, sanitizeMessageBody } from './common.ts'
import { sanitizeHttpBody } from '../httpBody.ts'

export const NATS_TCP_PORT = 4222

export function isNatsPortHint(src: number, dst: number): boolean {
  return src === NATS_TCP_PORT || dst === NATS_TCP_PORT
}

export function looksLikeNats(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 4) return false
  const head = decodeAscii(buffer, offset, Math.min(length, 16)).toUpperCase()
  return (
    head.startsWith('CONNECT')
    || head.startsWith('INFO')
    || head.startsWith('PUB ')
    || head.startsWith('HPUB ')
    || head.startsWith('SUB ')
    || head.startsWith('MSG ')
    || head.startsWith('HMSG ')
    || head.startsWith('PING')
    || head.startsWith('PONG')
    || head.startsWith('+OK')
    || head.startsWith('-ERR')
  )
}

export function sanitizeNats(
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
  if (!isNatsPortHint(srcPort, dstPort) && !looksLikeNats(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos < end) {
    // Find CRLF-terminated command line
    let lineEnd = pos
    while (lineEnd < end && buffer[lineEnd] !== 0x0a) lineEnd++
    const hasNl = lineEnd < end
    const lineLen = hasNl ? lineEnd - pos + 1 : end - pos
    if (lineLen <= 0) break

    // Trim CR for parsing
    let parseLen = lineLen
    if (hasNl && parseLen >= 2 && buffer[lineEnd - 1] === 0x0d) parseLen -= 2
    else if (hasNl) parseLen -= 1

    const line = decodeAscii(buffer, pos, Math.max(0, parseLen))
    const upper = line.toUpperCase()

    if (upper.startsWith('CONNECT')) {
      coverage.push({ protocol: 'nats', offset: pos, length: 7, status: 'covered' })
      let j = pos + 7
      while (j < pos + parseLen && (buffer[j] === 0x20 || buffer[j] === 0x09)) j++
      const jsonLen = pos + parseLen - j
      if (jsonLen > 0 && buffer[j] === 0x7b) {
        sanitizeConnectJson(
          buffer,
          j,
          jsonLen,
          collector,
          mapping,
          intents,
          packetIndex,
          highPrivacy,
          coverage,
          issues,
        )
      } else if (jsonLen > 0) {
        maskBytes(collector, intents, packetIndex, j, jsonLen, 'nats-connect', 'nats')
        coverage.push({ protocol: 'nats-auth', offset: j, length: jsonLen, status: 'redacted' })
      }
      pos += lineLen
      continue
    }

    if (
      upper.startsWith('PUB ')
      || upper.startsWith('HPUB ')
      || upper.startsWith('MSG ')
      || upper.startsWith('HMSG ')
    ) {
      coverage.push({
        protocol: 'nats',
        offset: pos,
        length: lineLen,
        status: 'covered',
      })
      // Map subject token (2nd field)
      const parts = line.trim().split(/\s+/)
      if (parts.length >= 2) {
        const subj = parts[1]!
        const subjOff = pos + line.indexOf(subj)
        if (subjOff >= pos && subj.length > 0) {
          mapAsciiIdentity(
            buffer,
            subjOff,
            subj.length,
            'opaque-id',
            collector,
            mapping,
            intents,
            packetIndex,
            'nats',
          )
          coverage.push({
            protocol: 'nats-subject',
            offset: subjOff,
            length: subj.length,
            status: 'covered',
          })
        }
      }
      const sizeTok = parts[parts.length - 1]!
      const payloadSize = Number.parseInt(sizeTok, 10)
      pos += lineLen
      if (Number.isFinite(payloadSize) && payloadSize >= 0 && pos + payloadSize <= end) {
        coverage.push(
          ...sanitizeMessageBody(
            buffer,
            pos,
            payloadSize,
            collector,
            mapping,
            intents,
            packetIndex,
            'nats',
            highPrivacy,
          ),
        )
        pos += payloadSize
        // trailing CRLF after payload
        if (pos + 1 < end && buffer[pos] === 0x0d && buffer[pos + 1] === 0x0a) pos += 2
        else if (pos < end && buffer[pos] === 0x0a) pos += 1
      }
      continue
    }

    if (
      upper.startsWith('SUB ')
      || upper.startsWith('UNSUB ')
      || upper.startsWith('INFO')
      || upper.startsWith('PING')
      || upper.startsWith('PONG')
      || upper.startsWith('+OK')
      || upper.startsWith('-ERR')
    ) {
      // INFO may contain URLs — mask unknown tails after command verb for INFO
      if (upper.startsWith('INFO')) {
        let j = pos + 4
        while (j < pos + parseLen && (buffer[j] === 0x20 || buffer[j] === 0x09)) j++
        coverage.push({ protocol: 'nats', offset: pos, length: j - pos, status: 'covered' })
        if (j < pos + parseLen) {
          maskBytes(
            collector,
            intents,
            packetIndex,
            j,
            pos + parseLen - j,
            'nats-info',
            'nats',
          )
          coverage.push({
            protocol: 'nats-body',
            offset: j,
            length: pos + parseLen - j,
            status: 'redacted',
          })
        }
      } else {
        coverage.push({ protocol: 'nats', offset: pos, length: lineLen, status: 'covered' })
      }
      pos += lineLen
      continue
    }

    // Unknown command → mask remainder fail-closed
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'nats-unknown', 'nats')
    coverage.push({
      protocol: 'nats-body',
      offset: pos,
      length: end - pos,
      status: 'redacted',
    })
    issues.push('nats-unknown-command')
    break
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'nats-session', 'nats')
    coverage.push({ protocol: 'nats', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}

function sanitizeConnectJson(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  highPrivacy: boolean,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  // Structured JSON path, then force-mask secret keys by scanning ASCII
  const result = sanitizeHttpBody({
    buffer,
    bodyAbsOffset: offset,
    bodyLength: length,
    headers: { contentType: 'application/json', contentEncoding: null, transferEncoding: null },
    collector,
    mapping,
    intents,
    packetIndex,
    highPrivacy,
  })
  coverage.push({
    protocol: 'nats-connect',
    offset,
    length,
    status: result.coverageStatus,
  })

  // Hard guarantee: pass / auth_token / jwt / nkey / sig values never survive.
  // Do not re-map `user` here — sanitizeHttpBody may already own those spans.
  maskJsonStringValues(
    buffer,
    offset,
    length,
    ['pass', 'password', 'auth_token', 'jwt', 'nkey', 'sig', 'token'],
    collector,
    intents,
    packetIndex,
  )
  issues.push('nats-connect-secrets')
  void highPrivacy
  void mapping
}

function maskJsonStringValues(
  buffer: Uint8Array,
  offset: number,
  length: number,
  keys: readonly string[],
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const text = decodeAscii(buffer, offset, length)
  for (const key of keys) {
    const re = new RegExp(`"${key}"\\s*:\\s*"([^"]*)"`, 'gi')
    let m: RegExpExecArray | null
    while ((m = re.exec(text)) !== null) {
      const val = m[1] ?? ''
      if (!val) continue
      const full = m[0]!
      const colon = full.indexOf(':')
      const q1 = full.indexOf('"', colon + 1)
      const valueStart = offset + (m.index ?? 0) + q1 + 1
      maskBytes(collector, intents, packetIndex, valueStart, val.length, 'nats-secret', 'nats')
    }
  }
}
