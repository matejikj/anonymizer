/**
 * T41 — XMPP (TCP 5222/5269): JID map; SASL mask; message/presence free text mask.
 * Bounded incremental scan — not a full XML DOM.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { asciiIndexOf, decodeAscii, mapAsciiIdentity, maskBytes } from './common.ts'

export const XMPP_CLIENT_PORT = 5222
export const XMPP_SERVER_PORT = 5269

export function isXmppPortHint(src: number, dst: number): boolean {
  return (
    src === XMPP_CLIENT_PORT
    || dst === XMPP_CLIENT_PORT
    || src === XMPP_SERVER_PORT
    || dst === XMPP_SERVER_PORT
  )
}

export function looksLikeXmpp(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 5) return false
  const head = decodeAscii(buffer, offset, Math.min(length, 64)).toLowerCase()
  return (
    head.includes('<stream:stream')
    || head.includes('<?xml')
    || head.includes('<auth ')
    || head.includes('<message')
    || head.includes('<presence')
    || head.includes('<iq ')
    || head.includes('<iq>')
  )
}

export function sanitizeXmpp(
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
  if (!isXmppPortHint(srcPort, dstPort) && !looksLikeXmpp(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length

  coverage.push({ protocol: 'xmpp', offset, length: Math.min(length, 1), status: 'covered' })

  // SASL <auth …>…</auth> — mask base64 content
  maskTagContents(buffer, offset, length, ['auth', 'response', 'challenge'], collector, intents, packetIndex, coverage, issues, 'xmpp-sasl')

  // Message/presence free text
  maskTagContents(
    buffer,
    offset,
    length,
    ['body', 'status', 'subject', 'nick', 'desc'],
    collector,
    intents,
    packetIndex,
    coverage,
    issues,
    'xmpp-body',
  )

  // JID attributes: from= / to= / jid=
  mapJidAttributes(buffer, offset, length, collector, mapping, intents, packetIndex, coverage)

  // vCard / unknown remaining sensitive blobs: if still contains canary-like long text inside
  // tags we didn't handle — leave structural XML, but mask CDATA blocks
  const cdata = asciiIndexOf(buffer, offset, length, '<![CDATA[')
  if (cdata >= 0) {
    const cend = asciiIndexOf(buffer, cdata, end - cdata, ']]>')
    if (cend > cdata) {
      const start = cdata + 9
      const len = cend - start
      if (len > 0) {
        maskBytes(collector, intents, packetIndex, start, len, 'xmpp-cdata', 'xmpp')
        coverage.push({ protocol: 'xmpp-body', offset: start, length: len, status: 'redacted' })
      }
    }
  }

  if (coverage.length <= 1) {
    // Mid-session binary / TLS residual — fail-closed
    maskBytes(collector, intents, packetIndex, offset, length, 'xmpp-session', 'xmpp')
    coverage.push({ protocol: 'xmpp', offset, length, status: 'redacted' })
    issues.push('xmpp-opaque-masked')
  }

  return { coverage, issues }
}

function maskTagContents(
  buffer: Uint8Array,
  offset: number,
  length: number,
  tags: readonly string[],
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
  protocol: string,
): void {
  const end = offset + length
  for (const tag of tags) {
    const openNeedle = `<${tag}`
    let search = offset
    while (search < end) {
      const open = asciiIndexOf(buffer, search, end - search, openNeedle)
      if (open < 0) break
      // find '>' of open tag
      let gt = open
      while (gt < end && buffer[gt] !== 0x3e) gt++
      if (gt >= end) break
      // self-closing?
      if (gt > open && buffer[gt - 1] === 0x2f) {
        search = gt + 1
        continue
      }
      const contentStart = gt + 1
      const closeNeedle = `</${tag}`
      const close = asciiIndexOf(buffer, contentStart, end - contentStart, closeNeedle)
      if (close < 0) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          contentStart,
          end - contentStart,
          protocol,
          'xmpp',
        )
        coverage.push({
          protocol,
          offset: contentStart,
          length: end - contentStart,
          status: 'redacted',
        })
        issues.push(`${protocol}-unclosed`)
        break
      }
      const contentLen = close - contentStart
      if (contentLen > 0) {
        maskBytes(collector, intents, packetIndex, contentStart, contentLen, protocol, 'xmpp')
        coverage.push({
          protocol,
          offset: contentStart,
          length: contentLen,
          status: 'redacted',
        })
        if (protocol === 'xmpp-sasl') issues.push('xmpp-sasl-masked')
      }
      search = close + closeNeedle.length
    }
  }
}

function mapJidAttributes(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  const text = decodeAscii(buffer, offset, length)
  const re = /\b(from|to|jid)=['"]([^'"]+)['"]/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const jid = m[2]!
    if (!jid) continue
    const jidStart = offset + (m.index ?? 0) + m[0]!.indexOf(jid)
    mapJidParts(buffer, jidStart, jid, collector, mapping, intents, packetIndex, coverage)
  }
}

function mapJidParts(
  buffer: Uint8Array,
  absOffset: number,
  jid: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  // user@domain/resource
  const slash = jid.indexOf('/')
  const bare = slash >= 0 ? jid.slice(0, slash) : jid
  const resource = slash >= 0 ? jid.slice(slash + 1) : ''
  const at = bare.indexOf('@')
  if (at > 0) {
    mapAsciiIdentity(
      buffer,
      absOffset,
      at,
      'user-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'xmpp',
    )
    coverage.push({ protocol: 'xmpp-jid', offset: absOffset, length: at, status: 'covered' })
    const domain = bare.slice(at + 1)
    if (domain.length > 0) {
      mapAsciiIdentity(
        buffer,
        absOffset + at + 1,
        domain.length,
        'hostname',
        collector,
        mapping,
        intents,
        packetIndex,
        'xmpp',
      )
      coverage.push({
        protocol: 'xmpp-jid',
        offset: absOffset + at + 1,
        length: domain.length,
        status: 'covered',
      })
    }
  } else if (bare.length > 0) {
    mapAsciiIdentity(
      buffer,
      absOffset,
      bare.length,
      'hostname',
      collector,
      mapping,
      intents,
      packetIndex,
      'xmpp',
    )
    coverage.push({
      protocol: 'xmpp-jid',
      offset: absOffset,
      length: bare.length,
      status: 'covered',
    })
  }
  if (resource.length > 0 && slash >= 0) {
    mapAsciiIdentity(
      buffer,
      absOffset + slash + 1,
      resource.length,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'xmpp',
    )
    coverage.push({
      protocol: 'xmpp-jid',
      offset: absOffset + slash + 1,
      length: resource.length,
      status: 'covered',
    })
  }
}
