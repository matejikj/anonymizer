/**
 * Shared Q.931 / QSIG identity field patching (T51).
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'
import { maskPayloadSpan } from '../../protocols/application/textproto'

export function mapQ931AsciiField(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: 'sip-phone' | 'person' | 'opaque-id',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  identityScopePrefixOrCanonPrefix?: string,
  explicitCanonPrefix?: string,
): void {
  void mapping
  let text = ''
  for (let i = 0; i < length; i++) {
    const c = buffer[offset + i]!
    if (c === 0) break
    if (c < 0x20 || c > 0x7e) {
      maskPayloadSpan(collector, offset, length, intents, packetIndex, `${protocolPrefix}-${category}`)
      return
    }
    text += String.fromCharCode(c)
  }
  if (!text) return
  const canonPrefix = explicitCanonPrefix ?? identityScopePrefixOrCanonPrefix
  const forCanon = canonPrefix ? `${canonPrefix}${text}` : text
  const canon = canonicalizeIdentity(category, forCanon) ?? forCanon
  const constraint = { kind: 'text-ascii' as const, byteLength: text.length }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, text.length, constraint, text)
  try {
    collector.addDeferred(
      offset,
      text.length,
      ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(
            offset,
            text.length,
            live.aliasFor(category, canon, constraint, text),
          )
        } catch {
          return createProtocolNeutralMaskFill({
            length: text.length,
            packetIndex,
            offset,
            domain: `${protocolPrefix}-${category}`,
          })
        }
      },
      {
        fallbackKind: category === 'sip-phone' ? 'digits' : 'text-x',
        protocol: protocolPrefix,
        category,
        packetIndex,
      },
    )
  } catch {
    /* overlap */
  }
  if (text.length < length) {
    maskPayloadSpan(
      collector,
      offset + text.length,
      length - text.length,
      intents,
      packetIndex,
      `${protocolPrefix}-pad`,
    )
  }
  void buffer
}

/** IA5 digit string or masked when non-digit. */
export function mapQ931PartyDigits(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  identityScopePrefix: string,
): 'mapped' | 'masked' | 'empty' {
  if (length <= 0) return 'empty'
  let ascii = true
  for (let i = 0; i < length; i++) {
    const c = buffer[offset + i]!
    if (c === 0) break
    if ((c < 0x30 || c > 0x39) && c !== 0x23 && c !== 0x2a) {
      ascii = false
      break
    }
  }
  if (ascii) {
    mapQ931AsciiField(
      buffer,
      offset,
      length,
      'sip-phone',
      collector,
      mapping,
      intents,
      packetIndex,
      protocolPrefix,
      identityScopePrefix,
    )
    return 'mapped'
  }
  maskPayloadSpan(collector, offset, length, intents, packetIndex, `${protocolPrefix}-party-bcd`)
  return 'masked'
}
