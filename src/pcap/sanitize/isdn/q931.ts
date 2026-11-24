/**
 * T51 — shared Q.931 DSS1 codec (numbers/display map; Facility/UU/keypad mask).
 * H.323 TPKT binding remains owned by T24; this module is the ISDN/QSIG/IUA child.
 *
 * QSIG Facility ROSE: pinned ECMA-143/165 operation dictionary baseline (T51); unknown ops
 * mask argument only. Non-BER Facility payloads fail-closed mask (`*-facility-mask`).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult, LayerCoverage } from '../types.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { maskPayloadSpan } from '../../protocols/application/textproto'
import { q931CallGraphForMapping } from './q931CallGraph.ts'
import { protocolGraphCaptureGeneration } from '../protocolGraphState.ts'
import { mapQ931AsciiField, mapQ931PartyDigits } from './q931IdentityFields.ts'
import { sanitizeQsigFacilityRose } from './qsigRoseSanitize.ts'

/** Q.931 protocol discriminator for user-network call control. */
export const Q931_PD = 0x08

const IE_CAUSE = 0x08
const IE_FACILITY = 0x1c
const IE_PROGRESS = 0x1e
const IE_DISPLAY = 0x28
const IE_KEYPAD = 0x2c
const IE_CONNECTED = 0x4c
const IE_CALLING = 0x6c
const IE_CALLING_SUB = 0x6d
const IE_CALLED = 0x70
const IE_CALLED_SUB = 0x71
const IE_REDIRECTING = 0x74
const IE_ORIGINAL = 0x73
const IE_USER_USER = 0x7e
const IE_BEARER = 0x04
const IE_CHANNEL = 0x18

export function looksLikeQ931(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 3) return false
  if (buffer[offset] !== Q931_PD) return false
  const crLen = buffer[offset + 1]! & 0x0f
  if (crLen > 15 || 2 + crLen + 1 > length) return false
  return true
}

export interface Q931SanitizeContext {
  /** D-channel / LAPD TEI+SAPI or transport session — isolates parallel links. */
  readonly linkScope: string
  /** Optional capture scope (defaults to linkScope + protocolPrefix). */
  readonly captureScopeKey?: string
}

export function sanitizeQ931(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix = 'q931',
  context?: Q931SanitizeContext,
): AppLayerResult | null {
  if (!looksLikeQ931(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const end = offset + length
  const linkScope = context?.linkScope ?? `${protocolPrefix}:unknown-link`
  const captureScopeKey =
    context?.captureScopeKey
    ?? `${protocolGraphCaptureGeneration()}/${protocolPrefix}`
  const identityScopePrefix = `${linkScope}/`

  const crLen = buffer[offset + 1]! & 0x0f
  const crOff = offset + 2
  const msgTypeOff = crOff + crLen
  if (msgTypeOff >= end) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, `${protocolPrefix}-hdr-trunc`)
    return {
      coverage: [{ protocol: protocolPrefix, offset, length, status: 'malformed' }],
      issues: [`${protocolPrefix}-hdr-trunc`],
    }
  }

  coverage.push({
    protocol: `${protocolPrefix}-hdr`,
    offset,
    length: 2,
    status: 'covered',
  })

  // Call reference: preserve length + direction bit (MSB of first CR octet); map value.
  if (crLen > 0) {
    const first = buffer[crOff]!
    const directionBit = first & 0x80
    const valueFirst = first & 0x7f
    // Map CR bytes as opaque (direction preserved by rewriting first octet after alias)
    mapCallReference(
      buffer,
      crOff,
      crLen,
      directionBit,
      valueFirst,
      collector,
      mapping,
      intents,
      packetIndex,
      protocolPrefix,
      coverage,
      linkScope,
    )
  }

  coverage.push({
    protocol: `${protocolPrefix}-msg`,
    offset: msgTypeOff,
    length: 1,
    status: 'covered',
  })

  const msgType = buffer[msgTypeOff]!
  let callRefValue = 0
  for (let i = 0; i < crLen; i++) {
    callRefValue = (callRefValue << 8) | (buffer[crOff + i]! & 0x7f)
  }
  const graph = q931CallGraphForMapping(mapping, captureScopeKey)
  const observed = graph.observe(linkScope, callRefValue, msgType, packetIndex)
  if (observed.multiLink) issues.push('q931-multi-link-graph')

  let pos = msgTypeOff + 1
  while (pos < end) {
    const iei = buffer[pos]!
    // Single-octet IE (Q.931 §4.5.1): bit 8 = 1
    if ((iei & 0x80) !== 0) {
      coverage.push({ protocol: `${protocolPrefix}-ie`, offset: pos, length: 1, status: 'covered' })
      pos += 1
      continue
    }
    if (pos + 1 >= end) {
      maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, `${protocolPrefix}-ie-trunc`)
      coverage.push({
        protocol: `${protocolPrefix}-ie`,
        offset: pos,
        length: end - pos,
        status: 'malformed',
      })
      issues.push(`${protocolPrefix}-ie-trunc`)
      break
    }
    const ieLen = buffer[pos + 1]!
    if (pos + 2 + ieLen > end) {
      maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, `${protocolPrefix}-ie-trunc`)
      coverage.push({
        protocol: `${protocolPrefix}-ie`,
        offset: pos,
        length: end - pos,
        status: 'malformed',
      })
      issues.push(`${protocolPrefix}-ie-trunc`)
      break
    }
    const dataOff = pos + 2
    coverage.push({
      protocol: `${protocolPrefix}-ie-hdr`,
      offset: pos,
      length: 2,
      status: 'covered',
    })

    switch (iei) {
      case IE_CALLING:
      case IE_CALLED:
      case IE_CONNECTED:
      case IE_REDIRECTING:
      case IE_ORIGINAL:
        sanitizeNumberIe(
          buffer,
          dataOff,
          ieLen,
          collector,
          mapping,
          intents,
          packetIndex,
          protocolPrefix,
          coverage,
          identityScopePrefix,
        )
        break
      case IE_CALLING_SUB:
      case IE_CALLED_SUB:
        sanitizeSubaddressIe(
          buffer,
          dataOff,
          ieLen,
          collector,
          mapping,
          intents,
          packetIndex,
          protocolPrefix,
          coverage,
          identityScopePrefix,
        )
        break
      case IE_DISPLAY:
        if (ieLen > 0) {
          mapQ931AsciiField(
            buffer,
            dataOff,
            ieLen,
            'person',
            collector,
            mapping,
            intents,
            packetIndex,
            protocolPrefix,
            identityScopePrefix,
          )
          coverage.push({
            protocol: `${protocolPrefix}-display`,
            offset: dataOff,
            length: ieLen,
            status: 'covered',
          })
        }
        break
      case IE_KEYPAD:
      case IE_USER_USER:
        if (ieLen > 0) {
          maskPayloadSpan(collector, dataOff, ieLen, intents, packetIndex, `${protocolPrefix}-content`)
          coverage.push({
            protocol: `${protocolPrefix}-body`,
            offset: dataOff,
            length: ieLen,
            status: 'redacted',
          })
          issues.push(`${protocolPrefix}-content-masked`)
        }
        break
      case IE_FACILITY:
        if (ieLen > 0) {
          const rose = sanitizeQsigFacilityRose(
            buffer,
            dataOff,
            ieLen,
            collector,
            mapping,
            intents,
            packetIndex,
            protocolPrefix,
            identityScopePrefix,
          )
          if (rose.structured) {
            coverage.push(...rose.coverage)
            issues.push(...rose.issues)
          } else {
            maskPayloadSpan(collector, dataOff, ieLen, intents, packetIndex, `${protocolPrefix}-facility`)
            coverage.push({
              protocol: `${protocolPrefix}-facility`,
              offset: dataOff,
              length: ieLen,
              status: 'redacted',
            })
            issues.push(`${protocolPrefix}-facility-mask`)
          }
        }
        break
      case IE_CAUSE:
      case IE_PROGRESS:
      case IE_BEARER:
      case IE_CHANNEL:
        coverage.push({
          protocol: `${protocolPrefix}-ie`,
          offset: dataOff,
          length: ieLen,
          status: 'covered',
        })
        break
      default:
        if (ieLen > 0) {
          maskPayloadSpan(collector, dataOff, ieLen, intents, packetIndex, `${protocolPrefix}-ie-${iei}`)
          coverage.push({
            protocol: `${protocolPrefix}-body`,
            offset: dataOff,
            length: ieLen,
            status: 'redacted',
          })
        }
        break
    }
    pos += 2 + ieLen
  }

  coverage.unshift({ protocol: protocolPrefix, offset, length, status: 'covered' })
  return { coverage, issues }
}

function mapCallReference(
  buffer: Uint8Array,
  offset: number,
  length: number,
  directionBit: number,
  _valueFirst: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  coverage: LayerCoverage[],
  linkScope: string,
): void {
  void _valueFirst
  // Build canonical from raw CR value with direction cleared for stable alias across reply.
  const raw: number[] = []
  for (let i = 0; i < length; i++) raw.push(buffer[offset + i]!)
  const normalized = raw.slice()
  if (normalized.length > 0) normalized[0] = normalized[0]! & 0x7f
  const hex = normalized.map((b) => b.toString(16).padStart(2, '0')).join('')
  const canon = canonicalizeIdentity('opaque-id', `isdn-cr:${linkScope}:${hex}`) ?? `isdn-cr:${linkScope}:${hex}`
  const aliasConstraint = { kind: 'text-ascii' as const, byteLength: Math.max(8, hex.length) }
  const aliasSpelling = hex.padEnd(aliasConstraint.byteLength, '0')
  intents?.recordEntityReplacement(
    packetIndex,
    offset,
    'opaque-id',
    canon,
    length,
    aliasConstraint,
    aliasSpelling,
  )
  try {
    collector.addDeferred(
      offset,
      length,
      ({ mapping: live }) => {
        try {
          // Binary CR: derive length-stable bytes from opaque alias; restore direction bit.
          const alias = live.aliasFor(
            'opaque-id',
            canon,
            aliasConstraint,
            aliasSpelling,
          )
          const out = new Uint8Array(length)
          let h = 2166136261 >>> 0
          for (let i = 0; i < alias.length; i++) {
            h ^= alias.charCodeAt(i)
            h = Math.imul(h, 16777619) >>> 0
          }
          for (let i = 0; i < length; i++) {
            h = Math.imul(h ^ (h >>> 13), 16777619) >>> 0
            out[i] = h & 0xff
          }
          out[0] = (out[0]! & 0x7f) | directionBit
          return out
        } catch {
          return createProtocolNeutralMaskFill({
            length,
            packetIndex,
            offset,
            domain: `${protocolPrefix}-cr`,
          })
        }
      },
      { fallbackKind: 'text-x', protocol: protocolPrefix, category: 'opaque-id', packetIndex },
    )
  } catch {
    /* overlap */
  }
  void mapping
  void buffer
  coverage.push({ protocol: `${protocolPrefix}-cr`, offset, length, status: 'covered' })
}

function numberHeaderLen(buffer: Uint8Array, offset: number, length: number): number {
  if (length < 1) return 0
  let n = 1
  // Consume type/plan (+ optional presentation) while extension bit clear
  while (n < length && n < 4 && (buffer[offset + n - 1]! & 0x80) === 0) n++
  return n
}

function sanitizeNumberIe(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  coverage: LayerCoverage[],
  identityScopePrefix: string,
): void {
  if (length < 1) return
  const hdr = numberHeaderLen(buffer, offset, length)
  coverage.push({
    protocol: `${protocolPrefix}-number-hdr`,
    offset,
    length: hdr,
    status: 'covered',
  })
  if (hdr >= length) return
  const digitOff = offset + hdr
  const digitLen = length - hdr
  let ascii = true
  for (let i = 0; i < digitLen; i++) {
    const c = buffer[digitOff + i]!
    if (c === 0) break
    if ((c < 0x30 || c > 0x39) && c !== 0x23 && c !== 0x2a) {
      ascii = false
      break
    }
  }
  if (ascii) {
    mapQ931PartyDigits(
      buffer,
      digitOff,
      digitLen,
      collector,
      mapping,
      intents,
      packetIndex,
      protocolPrefix,
      identityScopePrefix,
    )
    coverage.push({
      protocol: `${protocolPrefix}-number`,
      offset: digitOff,
      length: digitLen,
      status: 'covered',
    })
  } else {
    maskPayloadSpan(collector, digitOff, digitLen, intents, packetIndex, `${protocolPrefix}-number-bcd`)
    coverage.push({
      protocol: `${protocolPrefix}-number`,
      offset: digitOff,
      length: digitLen,
      status: 'redacted',
    })
  }
}

function sanitizeSubaddressIe(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  coverage: LayerCoverage[],
  identityScopePrefix: string,
): void {
  if (length < 1) return
  coverage.push({
    protocol: `${protocolPrefix}-sub-hdr`,
    offset,
    length: 1,
    status: 'covered',
  })
  if (length === 1) return
  mapQ931AsciiField(
    buffer,
    offset + 1,
    length - 1,
    'opaque-id',
    collector,
    mapping,
    intents,
    packetIndex,
    protocolPrefix,
    `${identityScopePrefix}isdn-sub:`,
  )
  coverage.push({
    protocol: `${protocolPrefix}-sub`,
    offset: offset + 1,
    length: length - 1,
    status: 'covered',
  })
}

