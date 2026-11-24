/**
 * Packet-number map for high-privacy drops via dropped bitset + rank checkpoints.
 */

import {
  anonymizedPacketNumberFromBitset,
  type CompactIndexArenas,
} from '../codec/compactIndexCodec'

export interface PacketNumberMap {
  readonly originalPacketCount: number
  readonly anonymizedPacketCount: number
  /** 1-based anonymized packet number, or null if dropped. */
  toAnonymized(originalPacketNumber: number): number | null
  /** 1-based original packet number for an anonymized packet, or null. */
  toOriginal(anonymizedPacketNumber: number): number | null
  isDroppedOriginal(originalPacketNumber: number): boolean
}

/**
 * Build map from compact index arenas.
 * Original packet numbers in the index are 1-based; bitset is 0-based indexes.
 */
export function buildPacketNumberMap(
  arenas: CompactIndexArenas,
  originalPacketCount: number,
  anonymizedPacketCount: number,
): PacketNumberMap {
  const anonToOriginal = new Int32Array(anonymizedPacketCount + 1)
  anonToOriginal.fill(-1)
  for (let origIndex = 0; origIndex < originalPacketCount; origIndex++) {
    const anon = anonymizedPacketNumberFromBitset(
      arenas.droppedBitset,
      arenas.rankCheckpoints,
      origIndex,
      originalPacketCount,
    )
    if (anon !== null && anon >= 1 && anon <= anonymizedPacketCount) {
      anonToOriginal[anon] = origIndex + 1
    }
  }

  return {
    originalPacketCount,
    anonymizedPacketCount,
    toAnonymized(originalPacketNumber: number) {
      if (originalPacketNumber < 1 || originalPacketNumber > originalPacketCount) return null
      return anonymizedPacketNumberFromBitset(
        arenas.droppedBitset,
        arenas.rankCheckpoints,
        originalPacketNumber - 1,
        originalPacketCount,
      )
    },
    toOriginal(anonymizedPacketNumber: number) {
      if (anonymizedPacketNumber < 1 || anonymizedPacketNumber > anonymizedPacketCount) return null
      const v = anonToOriginal[anonymizedPacketNumber]!
      return v > 0 ? v : null
    },
    isDroppedOriginal(originalPacketNumber: number) {
      return this.toAnonymized(originalPacketNumber) === null
    },
  }
}
