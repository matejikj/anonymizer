/**
 * T69 — apply free-text ops as length-preserving PCAP patches.
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector'
import type { IntentCollector } from '../../../discovery/intentCollector'
import type { MappingLike } from '../../../anonymization/mapping'
import { computeFixedLengthAsciiBytes } from '../../../sanitize/textPatch'
import type { FreeTextOp } from '../../../../engine/freeText/types.ts'

export interface ApplyFreeTextToCollectorInput {
  readonly ops: readonly FreeTextOp[]
  readonly absoluteOffset: number
  readonly collector: PatchCollector
  readonly mapping: MappingLike
  readonly intents?: IntentCollector
  readonly packetIndex: number
  readonly protocolId?: string
}

/**
 * Schedule deferred maps / masks. Preserve ops leave bytes untouched (ledger
 * treat unpatched covered spans as preserve-safe).
 */
export function applyFreeTextOpsToCollector(input: ApplyFreeTextToCollectorInput): {
  readonly mapCount: number
  readonly maskCount: number
  readonly preserveCount: number
} {
  const {
    ops,
    absoluteOffset,
    collector,
    intents,
    packetIndex,
    protocolId = 'free-text',
  } = input
  void input.mapping

  let mapCount = 0
  let maskCount = 0
  let preserveCount = 0

  for (const op of ops) {
    const abs = absoluteOffset + op.start
    const len = op.end - op.start
    if (len <= 0) continue

    if (op.kind === 'preserve') {
      preserveCount++
      continue
    }

    if (op.kind === 'mask') {
      maskCount++
      try {
        collector.add(abs, computeFixedLengthAsciiBytes(abs, len, '', 0x78))
      } catch {
        /* overlap with a prior structural patch */
      }
      intents?.recordMaskRange(packetIndex, abs, len, `${protocolId}-${op.reason}`, protocolId)
      continue
    }

    mapCount++
    const constraint = { kind: 'text-ascii' as const, byteLength: len }
    intents?.recordEntityReplacement(
      packetIndex,
      abs,
      op.category,
      op.canonical,
      len,
      constraint,
      op.spelling,
    )
    collector.addDeferred(abs, len, ({ mapping: live }) => {
      try {
        const mapped = live.aliasFor(op.category, op.canonical, constraint, op.spelling)
        if (mapped.length !== len) {
          return computeFixedLengthAsciiBytes(abs, len, '', 0x78)
        }
        return computeFixedLengthAsciiBytes(abs, len, mapped)
      } catch {
        return computeFixedLengthAsciiBytes(abs, len, '', 0x78)
      }
    }, {
      fallbackKind: 'text-x',
      protocol: protocolId,
      category: String(op.category),
      packetIndex,
    })
  }

  return { mapCount, maskCount, preserveCount }
}
