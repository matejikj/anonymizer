/**
 * Shared length-preserving ASCII identity map (T25 ISUP-adjacent paths, T37 T.30, RADIUS, H323, …).
 */

import type { IdentityCategory } from '../../../mapping/identityCategories'
import type { MappingLike } from '../../anonymization/mapping'
import type { IntentCollector } from '../../discovery/intentCollector'
import { canonicalizeIdentity } from '../../../mapping/canonicalize'
import type { PatchCollector } from '../PatchCollector'
import { createProtocolNeutralMaskFill } from '../maskFill'
import { computeFixedLengthAsciiBytes } from '../textPatch'

function latin1Slice(buffer: Uint8Array, abs: number, len: number): string {
  let s = ''
  for (let i = 0; i < len; i++) s += String.fromCharCode(buffer[abs + i]!)
  return s
}

export function mapLengthPreservingAsciiIdentity(
  buffer: Uint8Array,
  abs: number,
  len: number,
  category: IdentityCategory,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocol: string,
  domain: string,
  canonOverride?: string,
): boolean {
  void mapping
  if (len <= 0) return false
  const raw = latin1Slice(buffer, abs, len)
  const trimmed = raw.trimEnd()
  if (!trimmed) return false
  const canon = canonOverride ?? canonicalizeIdentity(category, trimmed) ?? trimmed
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len, constraint, raw)
  collector.addDeferred(
    abs,
    len,
    ({ mapping: live }) => {
      try {
        const alias = live.aliasFor(category, canon, constraint, raw)
        return computeFixedLengthAsciiBytes(abs, len, alias)
      } catch {
        return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain })
      }
    },
    {
      fallbackKind: category === 'sip-phone' ? 'digits' : 'text-x',
      protocol,
      category,
      packetIndex,
    },
  )
  return true
}
