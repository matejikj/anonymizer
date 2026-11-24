/**
 * Packed occurrence index with byte budget (Stage 19).
 * Stores (sourceId, location) references — never duplicates original strings.
 */

import { MAPPING_CAPABILITY_LIMITS } from '../domain/capabilityContract'
import type { OccurrenceRef } from './types'

export function occurrenceRefKey(ref: OccurrenceRef): string {
  if (ref.kind === 'text') {
    return `t:${ref.sourceId}:${ref.line}:${ref.start}:${ref.end}`
  }
  return `p:${ref.sourceId}:${ref.packetIndex}`
}

export function packedOccurrenceByteSize(ref: OccurrenceRef): number {
  const sourceBytes = new TextEncoder().encode(ref.sourceId).length
  if (ref.kind === 'text') {
    return 1 + 2 + sourceBytes + 4 + 4 + 4
  }
  return 1 + 2 + sourceBytes + 4
}

export class OccurrenceIndex {
  private bytesUsed = 0
  private readonly byIdentity = new Map<number, Set<string>>()
  private readonly keys = new Set<string>()

  getBytesUsed(): number {
    return this.bytesUsed
  }

  countForIdentity(identityId: number): number {
    return this.byIdentity.get(identityId)?.size ?? 0
  }

  occurrencesFor(identityId: number): readonly OccurrenceRef[] {
    const set = this.byIdentity.get(identityId)
    if (!set) return []
    const out: OccurrenceRef[] = []
    for (const key of set) {
      const ref = parseOccurrenceKey(key)
      if (ref) out.push(ref)
    }
    return out
  }

  wouldExceedBudget(ref: OccurrenceRef): boolean {
    const key = occurrenceRefKey(ref)
    if (this.keys.has(key)) return false
    const next = this.bytesUsed + packedOccurrenceByteSize(ref)
    return next > MAPPING_CAPABILITY_LIMITS.maxOccurrenceIndexBytes
  }

  append(identityId: number, ref: OccurrenceRef): boolean {
    const key = occurrenceRefKey(ref)
    if (this.keys.has(key)) return true

    const size = packedOccurrenceByteSize(ref)
    if (this.bytesUsed + size > MAPPING_CAPABILITY_LIMITS.maxOccurrenceIndexBytes) {
      return false
    }

    this.keys.add(key)
    this.bytesUsed += size
    let set = this.byIdentity.get(identityId)
    if (!set) {
      set = new Set()
      this.byIdentity.set(identityId, set)
    }
    set.add(key)
    return true
  }

  remove(identityId: number, ref: OccurrenceRef): boolean {
    const key = occurrenceRefKey(ref)
    const set = this.byIdentity.get(identityId)
    if (!set || !set.has(key)) return false

    set.delete(key)
    this.keys.delete(key)
    this.bytesUsed = Math.max(0, this.bytesUsed - packedOccurrenceByteSize(ref))
    if (set.size === 0) this.byIdentity.delete(identityId)
    return true
  }
}

function parseOccurrenceKey(key: string): OccurrenceRef | null {
  if (key.startsWith('t:')) {
    const parts = key.slice(2).split(':')
    if (parts.length < 4) return null
    const end = parts.pop()!
    const start = parts.pop()!
    const line = parts.pop()!
    const sourceId = parts.join(':')
    return {
      kind: 'text',
      sourceId,
      line: Number(line),
      start: Number(start),
      end: Number(end),
    }
  }
  if (key.startsWith('p:')) {
    const parts = key.slice(2).split(':')
    if (parts.length < 2) return null
    const packetIndex = Number(parts.pop())
    const sourceId = parts.join(':')
    return { kind: 'packet', sourceId, packetIndex }
  }
  return null
}
