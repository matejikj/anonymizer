/**
 * T18 — SSDP (UDP 1900): HTTP-like discovery via T15 tokenizer + header policy.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult } from './types'
import {
  tokenizeTextProtoMessage,
  dispositionForTextProtoHeader,
  applyPayloadMapHits,
  maskPayloadSpan,
  type TextProtoHeaderPolicyTable,
} from '../protocols/application/textproto'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { createProtocolNeutralMaskFill } from './maskFill'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { matchesGenericNotifyStartLine } from '../protocols/application/textproto/profiles/genericNotify'

const SSDP_PORTS = new Set([1900])

/** T18 SSDP header policy — USN UUID mapped; device type suffix preserved when separable. */
export const SSDP_HEADER_POLICY: TextProtoHeaderPolicyTable = {
  protocolId: 'ssdp',
  entries: [
    { name: 'host', action: { kind: 'detectors' } },
    { name: 'location', action: { kind: 'detectors' } },
    { name: 'callback', action: { kind: 'detectors' } },
    { name: 'server', action: { kind: 'mask' } },
    { name: 'user-agent', action: { kind: 'mask' } },
    { name: 'usn', action: { kind: 'detectors' } }, // UUID refined in sanitizeUuidBearingHeader
    { name: 'nts', action: { kind: 'preserve' } },
    { name: 'nt', action: { kind: 'preserve' } },
    { name: 'st', action: { kind: 'preserve' } },
    { name: 'man', action: { kind: 'preserve' } },
    { name: 'mx', action: { kind: 'structural' } },
    { name: 'content-length', action: { kind: 'structural' } },
    { name: 'content-type', action: { kind: 'structural' } },
    { name: 'cache-control', action: { kind: 'structural' } },
    { name: 'ext', action: { kind: 'structural' } },
  ],
  defaultAction: { kind: 'mask' },
}

export function isSsdpPortHint(src: number, dst: number): boolean {
  return SSDP_PORTS.has(src) || SSDP_PORTS.has(dst)
}

export function looksLikeSsdp(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 12) return false
  const head = new TextDecoder('latin1').decode(data.subarray(offset, offset + Math.min(length, 48)))
  return matchesGenericNotifyStartLine(head.split(/\r?\n/)[0] ?? head)
}

export function sanitizeSsdp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeSsdp(buffer, offset, length)) return null

  const msg = tokenizeTextProtoMessage(buffer, offset, length)
  if (!msg || !matchesGenericNotifyStartLine(msg.startLineText)) {
    return {
      coverage: [{ protocol: 'ssdp', offset, length, status: 'malformed' }],
      issues: ['ssdp-parse'],
    }
  }

  for (const h of msg.headers) {
    const action = dispositionForTextProtoHeader(SSDP_HEADER_POLICY, h.name)
    const abs = h.valueSpan.offset
    const len = h.valueSpan.length
    if (len <= 0) continue

    if (h.name === 'usn' || h.name === 'nt' || h.name === 'st') {
      sanitizeUuidBearingHeader(buffer, h.valueText, abs, len, collector, mapping, intents, packetIndex)
      continue
    }

    switch (action.kind) {
      case 'preserve':
      case 'structural':
        break
      case 'mask':
      case 'credential':
        maskPayloadSpan(collector, abs, len, intents, packetIndex, `ssdp-${h.name}`)
        break
      case 'map': {
        const canon = canonicalizeIdentity(action.category, h.valueText.trim())
        if (!canon) {
          maskPayloadSpan(collector, abs, len, intents, packetIndex, `ssdp-${h.name}`)
          break
        }
        applyPayloadMapHits([{
          category: action.category,
          absoluteOffset: abs,
          byteLength: len,
          originalSpelling: h.valueText,
          canonical: canon,
        }], collector, mapping, intents, packetIndex, 'ssdp')
        break
      }
      case 'detectors':
        // T63 — until free-text allowlist (T69), mask free header values entirely.
        maskPayloadSpan(collector, abs, len, intents, packetIndex, `ssdp-${h.name}`)
        break
      default:
        maskPayloadSpan(collector, abs, len, intents, packetIndex, `ssdp-${h.name}`)
    }
  }

  if (msg.body && msg.body.length > 0) {
    maskPayloadSpan(collector, msg.body.offset, msg.body.length, intents, packetIndex, 'ssdp-body')
  }

  // T63 — free detector values are fully masked; UUID mapped; structural preserved.
  return {
    coverage: [{ protocol: 'ssdp', offset, length, status: 'covered' }],
    issues: [],
  }
}

/**
 * Map uuid:… / urn:uuid:… segments as opaque-id; preserve ::device-type suffix.
 */
function sanitizeUuidBearingHeader(
  buffer: Uint8Array,
  value: string,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  void buffer
  // RFC-shaped UUID or shorter vendor uuid:token before ::type suffix
  const uuidRe = /(urn:)?uuid:([0-9a-fA-F-]{8,36}|[A-Za-z0-9._-]{4,64})/i
  const m = uuidRe.exec(value)
  if (!m) {
    // Standard upnp: / urn:schemas — preserve; vendor strings mask
    if (/^(upnp:|urn:schemas-)/i.test(value.trim())) return
    maskPayloadSpan(collector, abs, len, intents, packetIndex, 'ssdp-usn-opaque')
    return
  }
  const uuidToken = m[0]!
  const uuidRel = m.index!
  const uuidAbs = abs + uuidRel
  const uuidLen = uuidToken.length
  const body = (m[2] ?? '').toLowerCase()
  const hex = body.replace(/-/g, '')
  const canon = canonicalizeIdentity(
    'opaque-id',
    /^[0-9a-f]+$/.test(hex) && hex.length >= 8 ? hex : `uuid:${body}`,
  )
  if (!canon) {
    maskPayloadSpan(collector, uuidAbs, uuidLen, intents, packetIndex, 'ssdp-uuid')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: uuidLen }
  intents?.recordEntityReplacement(packetIndex, uuidAbs, 'opaque-id', canon, uuidLen, constraint, uuidToken)
  collector.addDeferred(uuidAbs, uuidLen, ({ mapping: live }) => {
    try {
      const alias = live.aliasFor('opaque-id', canon, constraint, uuidToken)
      // Keep uuid: / urn:uuid: prefix shape when possible
      if (/^urn:uuid:/i.test(uuidToken)) {
        const body = alias.replace(/^urn:uuid:/i, '').replace(/^uuid:/i, '')
        const rebuilt = `urn:uuid:${body}`.slice(0, uuidLen).padEnd(uuidLen, '0')
        return computeFixedLengthAsciiBytes(uuidAbs, uuidLen, rebuilt)
      }
      if (/^uuid:/i.test(uuidToken)) {
        const body = alias.replace(/^uuid:/i, '')
        const rebuilt = `uuid:${body}`.slice(0, uuidLen).padEnd(uuidLen, '0')
        return computeFixedLengthAsciiBytes(uuidAbs, uuidLen, rebuilt)
      }
      return computeFixedLengthAsciiBytes(uuidAbs, uuidLen, alias)
    } catch {
      return createProtocolNeutralMaskFill({
        length: uuidLen,
        packetIndex,
        offset: uuidAbs,
        domain: 'ssdp-uuid-fallback',
      })
    }
  }, { fallbackKind: 'text-x', protocol: 'ssdp', category: 'opaque-id', packetIndex })
  void mapping
}
