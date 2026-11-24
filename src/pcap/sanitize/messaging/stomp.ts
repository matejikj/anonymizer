/**
 * T41 — STOMP 1.2 (TCP 61613): CONNECT login/passcode; destination map; body JSON/mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { decodeAscii, mapAsciiIdentity, maskBytes, sanitizeMessageBody } from './common.ts'

export const STOMP_TCP_PORT = 61613

export function isStompPortHint(src: number, dst: number): boolean {
  return src === STOMP_TCP_PORT || dst === STOMP_TCP_PORT
}

export function looksLikeStomp(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 5) return false
  const head = decodeAscii(buffer, offset, Math.min(length, 12)).toUpperCase()
  return (
    head.startsWith('CONNECT')
    || head.startsWith('STOMP')
    || head.startsWith('SEND')
    || head.startsWith('SUBSCRIBE')
    || head.startsWith('MESSAGE')
    || head.startsWith('CONNECTED')
    || head.startsWith('ERROR')
    || head.startsWith('RECEIPT')
    || head.startsWith('ACK')
    || head.startsWith('NACK')
    || head.startsWith('DISCONNECT')
  )
}

export function sanitizeStomp(
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
  if (!isStompPortHint(srcPort, dstPort) && !looksLikeStomp(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos < end) {
    // Heartbeat: lone EOL
    if (buffer[pos] === 0x0a || (buffer[pos] === 0x0d && pos + 1 < end && buffer[pos + 1] === 0x0a)) {
      const hb = buffer[pos] === 0x0d ? 2 : 1
      coverage.push({ protocol: 'stomp', offset: pos, length: hb, status: 'covered' })
      pos += hb
      continue
    }

    // Command line
    let lineEnd = pos
    while (lineEnd < end && buffer[lineEnd] !== 0x0a) lineEnd++
    if (lineEnd >= end && lineEnd === pos) break
    const cmdLineLen = lineEnd < end ? lineEnd - pos + 1 : end - pos
    let cmdParse = cmdLineLen
    if (lineEnd < end && cmdParse >= 2 && buffer[lineEnd - 1] === 0x0d) cmdParse -= 2
    else if (lineEnd < end) cmdParse -= 1
    const command = decodeAscii(buffer, pos, Math.max(0, cmdParse)).trim().toUpperCase()
    coverage.push({ protocol: 'stomp', offset: pos, length: cmdLineLen, status: 'covered' })
    pos += cmdLineLen

    // Headers until blank line
    let contentLength: number | null = null
    while (pos < end) {
      if (buffer[pos] === 0x0a) {
        pos += 1
        break
      }
      if (buffer[pos] === 0x0d && pos + 1 < end && buffer[pos + 1] === 0x0a) {
        pos += 2
        break
      }
      let hEnd = pos
      while (hEnd < end && buffer[hEnd] !== 0x0a) hEnd++
      const hLen = hEnd < end ? hEnd - pos + 1 : end - pos
      let hParse = hLen
      if (hEnd < end && hParse >= 2 && buffer[hEnd - 1] === 0x0d) hParse -= 2
      else if (hEnd < end) hParse -= 1
      const header = decodeAscii(buffer, pos, Math.max(0, hParse))
      const colon = header.indexOf(':')
      if (colon > 0) {
        const key = header.slice(0, colon).trim().toLowerCase()
        const value = header.slice(colon + 1).trim()
        const valueOff = pos + header.indexOf(value, colon)
        if (key === 'passcode' || key === 'authorization') {
          if (value.length > 0 && valueOff >= pos) {
            maskBytes(
              collector,
              intents,
              packetIndex,
              valueOff,
              value.length,
              'stomp-passcode',
              'stomp',
            )
            coverage.push({
              protocol: 'stomp-auth',
              offset: valueOff,
              length: value.length,
              status: 'redacted',
            })
            issues.push('stomp-passcode-masked')
          }
        } else if (key === 'login') {
          if (value.length > 0 && valueOff >= pos) {
            mapAsciiIdentity(
              buffer,
              valueOff,
              value.length,
              'user-id',
              collector,
              mapping,
              intents,
              packetIndex,
              'stomp',
            )
            coverage.push({
              protocol: 'stomp-login',
              offset: valueOff,
              length: value.length,
              status: 'covered',
            })
          }
        } else if (
          key === 'destination'
          || key === 'subscription'
          || key === 'message-id'
          || key === 'receipt'
          || key === 'transaction'
          || key === 'id'
        ) {
          if (value.length > 0 && valueOff >= pos) {
            mapAsciiIdentity(
              buffer,
              valueOff,
              value.length,
              'opaque-id',
              collector,
              mapping,
              intents,
              packetIndex,
              'stomp',
            )
            coverage.push({
              protocol: 'stomp-header',
              offset: valueOff,
              length: value.length,
              status: 'covered',
            })
          }
        } else if (key === 'content-length') {
          const n = Number.parseInt(value, 10)
          if (Number.isFinite(n) && n >= 0) contentLength = n
          coverage.push({ protocol: 'stomp', offset: pos, length: hLen, status: 'covered' })
        } else if (value.length > 0 && valueOff >= pos) {
          // Unknown header values → mask
          maskBytes(
            collector,
            intents,
            packetIndex,
            valueOff,
            value.length,
            'stomp-header',
            'stomp',
          )
          coverage.push({
            protocol: 'stomp-header',
            offset: valueOff,
            length: value.length,
            status: 'redacted',
          })
        }
      }
      pos += hLen
      if (hEnd >= end) break
    }

    // Body
    if (contentLength !== null) {
      const bodyLen = Math.min(contentLength, end - pos)
      if (bodyLen > 0) {
        coverage.push(
          ...sanitizeMessageBody(
            buffer,
            pos,
            bodyLen,
            collector,
            mapping,
            intents,
            packetIndex,
            'stomp',
            highPrivacy,
          ),
        )
        pos += bodyLen
      }
      if (pos < end && buffer[pos] === 0) {
        coverage.push({ protocol: 'stomp', offset: pos, length: 1, status: 'covered' })
        pos += 1
      }
    } else {
      // NUL-terminated body
      let nul = pos
      while (nul < end && buffer[nul] !== 0) nul++
      const bodyLen = nul - pos
      if (bodyLen > 0) {
        if (
          command === 'CONNECT'
          || command === 'STOMP'
          || command === 'CONNECTED'
          || command === 'SUBSCRIBE'
          || command === 'UNSUBSCRIBE'
          || command === 'ACK'
          || command === 'NACK'
          || command === 'BEGIN'
          || command === 'COMMIT'
          || command === 'ABORT'
          || command === 'DISCONNECT'
          || command === 'RECEIPT'
        ) {
          // empty / control — no body content expected
          if (bodyLen > 0) {
            maskBytes(collector, intents, packetIndex, pos, bodyLen, 'stomp-body', 'stomp')
            coverage.push({
              protocol: 'stomp-body',
              offset: pos,
              length: bodyLen,
              status: 'redacted',
            })
          }
        } else {
          coverage.push(
            ...sanitizeMessageBody(
              buffer,
              pos,
              bodyLen,
              collector,
              mapping,
              intents,
              packetIndex,
              'stomp',
              highPrivacy,
            ),
          )
        }
        pos = nul
      }
      if (pos < end && buffer[pos] === 0) {
        coverage.push({ protocol: 'stomp', offset: pos, length: 1, status: 'covered' })
        pos += 1
      }
    }

    // Optional trailing EOL after frame
    if (pos < end && buffer[pos] === 0x0a) pos += 1
    else if (pos + 1 < end && buffer[pos] === 0x0d && buffer[pos + 1] === 0x0a) pos += 2
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'stomp-session', 'stomp')
    coverage.push({ protocol: 'stomp', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}
