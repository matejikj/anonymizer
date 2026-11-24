/**
 * Compressed per-entity packet occurrence index (Stage 10).
 */

import { MAPPING_CAPABILITY_LIMITS, MAX_ENTITY_CARDINALITY } from '../../domain/capabilityContract'
import type { EntityOccurrenceIndex } from './types'

export class PackedEntityOccurrenceIndex implements EntityOccurrenceIndex {
  private readonly map = new Map<string, Uint32Array>()
  private _overflow = false
  private _byteSize = 0

  get overflow(): boolean {
    return this._overflow
  }

  get byteSize(): number {
    return this._byteSize
  }

  static fromLists(entries: ReadonlyMap<string, readonly number[]>): PackedEntityOccurrenceIndex {
    const idx = new PackedEntityOccurrenceIndex()
    for (const [key, packets] of entries) {
      idx.set(key, packets)
    }
    return idx
  }

  set(entityKey: string, packetIndices: readonly number[]): void {
    if (this._overflow) return
    const sorted = [...new Set(packetIndices)].sort((a, b) => a - b)
    const bytes = sorted.length * 4
    if (this.map.size >= MAX_ENTITY_CARDINALITY || this._byteSize + bytes > MAPPING_CAPABILITY_LIMITS.maxOccurrenceIndexBytes) {
      this._overflow = true
      return
    }
    const arr = new Uint32Array(sorted)
    this._byteSize += arr.byteLength
    this.map.set(entityKey, arr)
  }

  add(entityKey: string, packetIndex: number): void {
    const existing = this.map.get(entityKey)
    if (!existing) {
      this.set(entityKey, [packetIndex])
      return
    }
    if (existing.includes(packetIndex)) return
    this._byteSize -= existing.byteLength
    this.map.delete(entityKey)
    this.set(entityKey, [...existing, packetIndex])
  }

  packetsForEntity(entityKey: string): readonly number[] {
    const arr = this.map.get(entityKey)
    return arr ? Array.from(arr) : []
  }

  hasEntity(entityKey: string, packetIndex: number): boolean {
    const arr = this.map.get(entityKey)
    if (!arr) return false
    // arr is always sorted ascending (see set()), so binary search is valid — this is
    // hit up to several times per rendered/colored packet, and a linear scan over a hot
    // entity's occurrence list (which can be most of the capture) dominates PCAP UI cost.
    let lo = 0
    let hi = arr.length - 1
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1
      const v = arr[mid]!
      if (v === packetIndex) return true
      if (v < packetIndex) lo = mid + 1
      else hi = mid - 1
    }
    return false
  }

  *entityKeys(): IterableIterator<string> {
    yield* this.map.keys()
  }

  toMap(): ReadonlyMap<string, readonly number[]> {
    const out = new Map<string, readonly number[]>()
    for (const [k, v] of this.map) out.set(k, Array.from(v))
    return out
  }
}

export function buildOccurrenceIndexFromIntents(
  entities: ReadonlyArray<{ key: string; firstPacket: number }>,
  entityPacketLists: ReadonlyMap<string, readonly number[]>,
  intentPacketIndices: ReadonlyArray<{ entityKey: string; packetIndex: number }>,
): PackedEntityOccurrenceIndex {
  const lists = new Map<string, number[]>()

  for (const e of entities) {
    const fromRegistry = entityPacketLists.get(e.key)
    if (fromRegistry && fromRegistry.length > 0) {
      lists.set(e.key, [...fromRegistry])
    } else {
      lists.set(e.key, [])
    }
  }

  // Duplicates are cheap here (a plain push) — final dedup + sort happens
  // once in PackedEntityOccurrenceIndex.set() via `[...new Set(...)]`, so an
  // O(n) `.includes()` scan per push (O(n^2) overall for hot entities) isn't
  // needed to keep the result correct.
  for (const { entityKey, packetIndex } of intentPacketIndices) {
    const cur = lists.get(entityKey)
    if (cur) {
      cur.push(packetIndex)
    } else {
      lists.set(entityKey, [packetIndex])
    }
  }

  return PackedEntityOccurrenceIndex.fromLists(lists)
}
