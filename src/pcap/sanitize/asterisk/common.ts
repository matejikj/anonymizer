/**
 * T50 — shared helpers for Asterisk AMI / ARI sanitizers.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'

export type AmiMapCategory = 'opaque-id' | 'user-id' | 'hostname' | 'sip-phone' | 'person'

export function maskBytes(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
  protocol: string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  try {
    collector.add(offset, fill)
  } catch {
    /* overlap */
  }
  intents?.recordMaskRange(packetIndex, offset, length, domain, protocol)
}

export function mapAsciiIdentity(
  buffer: Uint8Array,
  offset: number,
  length: number,
  category: AmiMapCategory,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
  canonicalPrefix?: string,
): void {
  if (length <= 0) return
  const raw = new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
  const token = raw.replace(/\0+$/g, '').replace(/^["']|["']$/g, '')
  if (!token) {
    maskBytes(collector, intents, packetIndex, offset, length, `${protocol}-empty`, protocol)
    return
  }
  const forCanon = canonicalPrefix ? `${canonicalPrefix}${token}` : token
  const canon = canonicalizeIdentity(category, forCanon) ?? forCanon
  const constraint = { kind: 'text-ascii' as const, byteLength: length }
  intents?.recordEntityReplacement(packetIndex, offset, category, canon, length, constraint, token)
  try {
    collector.addDeferred(
      offset,
      length,
      ({ mapping: live }) => {
        try {
          return computeFixedLengthAsciiBytes(
            offset,
            length,
            live.aliasFor(category, canon, constraint, token),
          )
        } catch {
          return createProtocolNeutralMaskFill({
            length,
            packetIndex,
            offset,
            domain: `${protocol}-${category}`,
          })
        }
      },
      { fallbackKind: 'text-x', protocol, category, packetIndex },
    )
  } catch {
    /* overlap with prior HTTP/JSON pass — keep first writer */
  }
  void mapping
  void buffer
}

export function decodeAscii(buffer: Uint8Array, offset: number, length: number): string {
  return new TextDecoder('ascii', { fatal: false }).decode(buffer.subarray(offset, offset + length))
}
