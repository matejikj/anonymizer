/**
 * T18 — WS-Discovery (UDP 3702): SOAP XML — map urn:uuid / URL / scopes via detectors.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import {
  detectIdentitiesInPayload,
  applyPayloadMapHits,
  hitsFromDetectors,
  maskPayloadSpan,
} from '../protocols/application/textproto'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizeIdentity } from '../../mapping/canonicalize'

const WSD_PORTS = new Set([3702])

export function isWsDiscoveryPortHint(src: number, dst: number): boolean {
  return WSD_PORTS.has(src) || WSD_PORTS.has(dst)
}

export function looksLikeWsDiscovery(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 32) return false
  const head = new TextDecoder('latin1').decode(data.subarray(offset, offset + Math.min(length, 256)))
  // SOAP / WS-Discovery without DTD
  if (/<!DOCTYPE/i.test(head) || /<!ENTITY/i.test(head)) return false
  return (
    /Envelope/i.test(head)
    && (/Probe|Resolve|Hello|Bye|wsa:|wsd:/i.test(head) || /schemas\.xmlsoap\.org/i.test(head))
  )
}

export function sanitizeWsDiscovery(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeWsDiscovery(buffer, offset, length)) return null

  const text = new TextDecoder('latin1').decode(buffer.subarray(offset, offset + length))
  if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'wsd-xxe-reject')
    return {
      coverage: [{ protocol: 'ws-discovery', offset, length, status: 'malformed' }],
      issues: ['wsd-dtd-forbidden'],
    }
  }

  // UUID addresses (MessageID / EndpointReference / RelatesTo)
  const uuidRe = /urn:uuid:([0-9a-fA-F-]{36}|[0-9a-fA-F]{32})/gi
  let m: RegExpExecArray | null
  while ((m = uuidRe.exec(text)) !== null) {
    const token = m[0]!
    const abs = offset + m.index!
    const hex = (m[1] ?? '').replace(/-/g, '').toLowerCase()
    const canon = canonicalizeIdentity('opaque-id', hex.length >= 8 ? hex : token.toLowerCase())
    if (!canon) continue
    const constraint = { kind: 'text-ascii' as const, byteLength: token.length }
    intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, token.length, constraint, token)
    collector.addDeferred(abs, token.length, ({ mapping: live }) => {
      try {
        const alias = live.aliasFor('opaque-id', canon, constraint, token)
        const body = alias.replace(/^urn:uuid:/i, '')
        const rebuilt = `urn:uuid:${body}`.slice(0, token.length).padEnd(token.length, '0')
        return computeFixedLengthAsciiBytes(abs, token.length, rebuilt)
      } catch {
        return createProtocolNeutralMaskFill({
          length: token.length,
          packetIndex,
          offset: abs,
          domain: 'wsd-uuid',
        })
      }
    }, { fallbackKind: 'text-x', protocol: 'ws-discovery', category: 'opaque-id', packetIndex })
  }

  // XAddrs / http(s) URLs — detectors
  const hits = detectIdentitiesInPayload(buffer, offset, length)
  applyPayloadMapHits(hitsFromDetectors(hits), collector, mapping, intents, packetIndex, 'ws-discovery')

  // Scopes often carry site/org names — mask unknown free text between tags when high density?
  // Baseline: leave non-hit XML structure; unknown attribute values already often caught by detectors.

  const coverage: LayerCoverage[] = [{
    protocol: 'ws-discovery',
    offset,
    length,
    status: 'covered',
  }]
  return { coverage, issues: [] }
}
