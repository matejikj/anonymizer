/**
 * T50 — Asterisk Manager Interface (AMI v2): TCP 5038; Login secrets; channel/caller map.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { decodeAscii, mapAsciiIdentity, maskBytes, type AmiMapCategory } from './common.ts'
import { amiEventListTrackerForTransport } from './amiEventList.ts'

export const AMI_TCP_PORT = 5038

const BANNER_RE = /^Asterisk Call Manager\//i

/** Keys whose values are secrets (both levels). */
const SECRET_KEYS = new Set([
  'secret',
  'key',
  'challenge',
  'password',
  'auth',
  'md5secret',
])

/** Keys → map category / namespace prefix. */
const MAP_KEYS: ReadonlyMap<string, { category: AmiMapCategory; prefix: string }> = new Map([
  ['calleridnum', { category: 'sip-phone', prefix: '' }],
  ['connectedlinenum', { category: 'sip-phone', prefix: '' }],
  ['exten', { category: 'opaque-id', prefix: 'ami-exten:' }],
  ['extension', { category: 'opaque-id', prefix: 'ami-exten:' }],
  ['dialstring', { category: 'opaque-id', prefix: 'ami-dial:' }],
  ['calleridname', { category: 'person', prefix: '' }],
  ['connectedlinename', { category: 'person', prefix: '' }],
  ['channel', { category: 'opaque-id', prefix: 'ami-chan:' }],
  ['destchannel', { category: 'opaque-id', prefix: 'ami-chan:' }],
  ['destination', { category: 'opaque-id', prefix: 'ami-chan:' }],
  ['uniqueid', { category: 'opaque-id', prefix: 'ami-uid:' }],
  ['linkedid', { category: 'opaque-id', prefix: 'ami-lid:' }],
  ['bridgeuniqueid', { category: 'opaque-id', prefix: 'ami-bridge:' }],
  ['bridgeid', { category: 'opaque-id', prefix: 'ami-bridge:' }],
  ['actionid', { category: 'opaque-id', prefix: 'ami-action:' }],
  ['username', { category: 'user-id', prefix: '' }],
  ['accountcode', { category: 'opaque-id', prefix: 'ami-acct:' }],
  ['context', { category: 'opaque-id', prefix: 'ami-ctx:' }],
  ['queue', { category: 'opaque-id', prefix: 'ami-queue:' }],
  ['membername', { category: 'person', prefix: '' }],
  ['interface', { category: 'opaque-id', prefix: 'ami-iface:' }],
])

const CONTENT_MASK_KEYS = new Set([
  'digits',
  'dtmf',
  'variable',
  'value',
  'message',
  'output',
  'command',
  'userevent',
])

/** Preserve structural keys (no value rewrite). */
const PRESERVE_KEYS = new Set([
  'action',
  'event',
  'response',
  'channelstate',
  'channelstatedesc',
  'cause',
  'causetxt',
  'privilege',
  'eventlist',
  'listitems',
])

export function isAmiPortHint(src: number, dst: number): boolean {
  return src === AMI_TCP_PORT || dst === AMI_TCP_PORT
}

export function looksLikeAmi(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 16) return false
  const head = decodeAscii(buffer, offset, Math.min(length, 96))
  if (BANNER_RE.test(head)) return true
  // Action:/Event:/Response: packet without banner (mid-stream)
  return /^(?:Action|Event|Response): /im.test(head)
}

export interface AmiSanitizeContext {
  readonly transportSessionKey: string
}

export function sanitizeAmi(
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
  context?: AmiSanitizeContext,
): AppLayerResult | null {
  if (!isAmiPortHint(srcPort, dstPort) && !looksLikeAmi(buffer, offset, length)) return null
  if (!looksLikeAmi(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  // Banner line
  if (BANNER_RE.test(decodeAscii(buffer, pos, Math.min(end - pos, 64)))) {
    let nl = pos
    while (nl < end && buffer[nl] !== 0x0a) nl++
    const lineEnd = nl < end ? nl + 1 : end
    coverage.push({ protocol: 'ami', offset: pos, length: lineEnd - pos, status: 'covered' })
    pos = lineEnd
  }

  while (pos < end) {
    // Find message end \r\n\r\n or \n\n
    let msgEnd = findAmiMessageEnd(buffer, pos, end)
    if (msgEnd < 0) {
      // Incomplete trailing message — sanitize what we have
      msgEnd = end
    }
    const msgLen = msgEnd - pos
    if (msgLen <= 0) break
    sanitizeAmiMessage(
      buffer,
      pos,
      msgLen,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
      context,
    )
    coverage.push({ protocol: 'ami', offset: pos, length: msgLen, status: 'covered' })
    pos = msgEnd
    // skip extra blank lines
    while (pos < end && (buffer[pos] === 0x0d || buffer[pos] === 0x0a)) pos++
  }

  if (coverage.length === 0) return null
  coverage.push({ protocol: 'ami', offset, length, status: 'covered' })
  return { coverage, issues }
}

function findAmiMessageEnd(buffer: Uint8Array, start: number, end: number): number {
  for (let i = start; i + 3 < end; i++) {
    if (
      buffer[i] === 0x0d
      && buffer[i + 1] === 0x0a
      && buffer[i + 2] === 0x0d
      && buffer[i + 3] === 0x0a
    ) {
      return i + 4
    }
  }
  for (let i = start; i + 1 < end; i++) {
    if (buffer[i] === 0x0a && buffer[i + 1] === 0x0a) return i + 2
  }
  return -1
}

function sanitizeAmiMessage(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
  context: AmiSanitizeContext | undefined,
): void {
  const text = decodeAscii(buffer, offset, length)
  const transportKey = context?.transportSessionKey ?? 'ami:unknown-transport'
  const eventListTracker = amiEventListTrackerForTransport(mapping, transportKey)
  let msgKind: 'event' | 'action' | 'response' | 'other' = 'other'
  let messageActionId: string | undefined
  let lineStart = 0
  while (lineStart < text.length) {
    let lineEnd = text.indexOf('\n', lineStart)
    if (lineEnd < 0) lineEnd = text.length
    let line = text.slice(lineStart, lineEnd)
    if (line.endsWith('\r')) line = line.slice(0, -1)
    const absLine = offset + lineStart
    if (line.length === 0) {
      lineStart = lineEnd + 1
      continue
    }
    const colon = line.indexOf(':')
    if (colon <= 0) {
      // CLI / multiline garbage — mask whole line (anti Event: injection in Command output)
      maskBytes(collector, intents, packetIndex, absLine, line.length, 'ami-cli', 'ami')
      coverage.push({
        protocol: 'ami-body',
        offset: absLine,
        length: line.length,
        status: 'redacted',
      })
      lineStart = lineEnd + 1
      continue
    }
    const key = line.slice(0, colon).trim()
    const keyLower = key.toLowerCase()
    if (keyLower === 'event') msgKind = 'event'
    else if (keyLower === 'action') msgKind = 'action'
    else if (keyLower === 'response') msgKind = 'response'
    // Value starts after ": " or ":"
    let valueStartInLine = colon + 1
    if (line[valueStartInLine] === ' ') valueStartInLine++
    const value = line.slice(valueStartInLine)
    const valueAbs = absLine + valueStartInLine
    const valueLen = value.length
    if (keyLower === 'actionid') messageActionId = value

    if (keyLower === 'eventlist' && value.toLowerCase() === 'start') {
      issues.push('ami-eventlist-start')
    }
    if (keyLower === 'listitems') {
      const n = Number.parseInt(value, 10)
      if (Number.isFinite(n)) {
        const actionIdLine = text.match(/^ActionID:\s*(\S+)/im)
        const actionId = actionIdLine?.[1] ?? `pkt-${packetIndex}`
        eventListTracker.start(actionId, n)
        issues.push('ami-eventlist-items')
      }
    }
    if (keyLower === 'eventlist' && value.toLowerCase() === 'complete') {
      const actionIdLine = text.match(/^ActionID:\s*(\S+)/im)
      const actionId = actionIdLine?.[1] ?? `pkt-${packetIndex}`
      eventListTracker.complete(actionId)
      issues.push('ami-eventlist-terminal')
    }

    if (valueLen === 0 || PRESERVE_KEYS.has(keyLower)) {
      if (keyLower === 'actionid' && text.toLowerCase().includes('eventlist: start')) {
        // correlated below on child events
      }
      coverage.push({ protocol: 'ami', offset: absLine, length: line.length, status: 'covered' })
      lineStart = lineEnd + 1
      continue
    }

    if (SECRET_KEYS.has(keyLower)) {
      maskBytes(collector, intents, packetIndex, valueAbs, valueLen, 'ami-secret', 'ami')
      coverage.push({
        protocol: 'ami-auth',
        offset: valueAbs,
        length: valueLen,
        status: 'redacted',
      })
      issues.push('ami-secret-masked')
      lineStart = lineEnd + 1
      continue
    }

    if (CONTENT_MASK_KEYS.has(keyLower)) {
      // Variable: NAME=value — mask after first '='
      if (keyLower === 'variable') {
        const eq = value.indexOf('=')
        if (eq >= 0 && eq + 1 < valueLen) {
          maskBytes(
            collector,
            intents,
            packetIndex,
            valueAbs + eq + 1,
            valueLen - eq - 1,
            'ami-var',
            'ami',
          )
          coverage.push({
            protocol: 'ami-var',
            offset: valueAbs + eq + 1,
            length: valueLen - eq - 1,
            status: 'redacted',
          })
        } else {
          maskBytes(collector, intents, packetIndex, valueAbs, valueLen, 'ami-var', 'ami')
        }
      } else {
        maskBytes(collector, intents, packetIndex, valueAbs, valueLen, 'ami-content', 'ami')
        coverage.push({
          protocol: 'ami-body',
          offset: valueAbs,
          length: valueLen,
          status: 'redacted',
        })
      }
      lineStart = lineEnd + 1
      continue
    }

    const mapSpec = MAP_KEYS.get(keyLower)
    if (mapSpec) {
      let category = mapSpec.category
      let prefix = mapSpec.prefix
      // Phone-shaped Exten
      if (
        (keyLower === 'exten' || keyLower === 'extension' || keyLower === 'dialstring')
        && (/^\+?\d{6,}$/.test(value) || /^tel:/i.test(value))
      ) {
        category = 'sip-phone'
        prefix = ''
      }
      mapAsciiIdentity(
        buffer,
        valueAbs,
        valueLen,
        category,
        collector,
        mapping,
        intents,
        packetIndex,
        'ami',
        prefix || undefined,
      )
      coverage.push({
        protocol: 'ami-id',
        offset: valueAbs,
        length: valueLen,
        status: 'covered',
      })
      lineStart = lineEnd + 1
      continue
    }

    // Unknown key — fail-closed mask value (never silent preserve of free text)
    maskBytes(collector, intents, packetIndex, valueAbs, valueLen, 'ami-unknown', 'ami')
    coverage.push({
      protocol: 'ami-body',
      offset: valueAbs,
      length: valueLen,
      status: 'redacted',
    })
    lineStart = lineEnd + 1
  }

  if (msgKind === 'event' && messageActionId) {
    const progress = eventListTracker.event(messageActionId)
    if (progress) {
      issues.push(progress.complete ? 'ami-eventlist-complete' : 'ami-eventlist-child')
    }
  }
}
