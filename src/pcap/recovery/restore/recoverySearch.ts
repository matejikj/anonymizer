/**
 * Recovery search orchestration (step 7) — index only, never DATA frames / network.
 */

import { recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import type {
  RecoveryHit,
  RecoveryQueryCandidate,
  RecoveryResultPage,
} from '../domain/types'
import { extractRecoveryQuery, normalizeLookupKey } from './queryExtractor'
import type { UnlockedLookupIndex } from './unlockedLookupIndex'

export function searchUnlockedIndex(input: {
  index: UnlockedLookupIndex
  query: string
  offset?: number
  limit?: number
}): PcapRecoveryResult<RecoveryResultPage> {
  const extracted = extractRecoveryQuery(input.query)
  if (!extracted.ok) return extracted

  const packetCandidates = extracted.value.candidates.filter((c) => c.kind === 'packet')
  const valueCandidates = extracted.value.candidates.filter((c) => c.kind === 'value')

  const hits: RecoveryHit[] = []
  let hitSeq = 0
  const push = (h: Omit<RecoveryHit, 'hitId'>) => {
    hits.push({ ...h, hitId: `h${hitSeq++}` })
  }

  // Combine value + nearby packet context when both present.
  const contextPackets = new Set(
    packetCandidates.map((c) => (c.kind === 'packet' ? c.anonymizedPacketNumber : -1)),
  )

  for (const cand of valueCandidates) {
    if (cand.kind !== 'value') continue
    const key = normalizeLookupKey(cand.text)
    let entryIndexes = input.index.lookupExact(key)
    if (entryIndexes.length === 0) {
      entryIndexes = input.index.lookupExactWire(key)
    }
    if (entryIndexes.length === 0) continue

    const narrowed = narrowByPacketContext(input.index, entryIndexes, contextPackets)
    emitValueHits(input.index, cand, narrowed.indexes, narrowed.usedContext, push)
  }

  // Packet-only candidates (no value match required).
  for (const cand of packetCandidates) {
    if (cand.kind !== 'packet') continue
    // Skip if already used as context for a value hit that covered this packet.
    const entries = input.index.lookupByAnonymizedPacket(cand.anonymizedPacketNumber)
    const originalPn = input.index.packetMap.toOriginal(cand.anonymizedPacketNumber)
    if (entries.length === 0) {
      push({
        status: 'packet-only',
        category: 'unknown',
        matchKind: 'none',
        queriedValue: `packet ${cand.anonymizedPacketNumber}`,
        anonymizedPacketNumber: cand.anonymizedPacketNumber,
        originalPacketNumber: originalPn ?? undefined,
        candidateCount: 0,
      })
      continue
    }
    // Don't dump all entries — report packet mapping + ambiguous if multiple identities.
    if (entries.length === 1) {
      const entry = input.index.getEntry(entries[0]!)
      if (!entry) continue
      const ambiguous = entry.matchKind === 'ambiguous' || entry.matchKind === 'redacted'
      push({
        status: ambiguous ? entry.matchKind : 'exact',
        category: entry.category,
        matchKind: entry.matchKind,
        queriedValue: `packet ${cand.anonymizedPacketNumber}`,
        originalValue: ambiguous ? undefined : entry.originalCanonical,
        originalWire: ambiguous ? undefined : entry.originalWire,
        anonymizedCanonical: entry.anonymizedCanonical,
        anonymizedPacketNumber: cand.anonymizedPacketNumber,
        originalPacketNumber: originalPn ?? undefined,
        candidateCount: 1,
        entryIndex: entry.entryIndex,
      })
    } else {
      push({
        status: 'ambiguous',
        category: 'unknown',
        matchKind: 'ambiguous',
        queriedValue: `packet ${cand.anonymizedPacketNumber}`,
        anonymizedPacketNumber: cand.anonymizedPacketNumber,
        originalPacketNumber: originalPn ?? undefined,
        candidateCount: entries.length,
      })
    }
  }

  const offset = Math.max(0, input.offset ?? 0)
  const limit = Math.min(
    PCAP_RECOVERY_LIMITS.maxResultPageSize,
    Math.max(1, input.limit ?? PCAP_RECOVERY_LIMITS.maxResultPageSize),
  )
  const pageHits = hits.slice(offset, offset + limit)
  const nextOffset = offset + limit < hits.length ? offset + limit : null

  return recoveryOk({
    hits: pageHits,
    totalHits: hits.length,
    offset,
    limit,
    truncated: extracted.value.truncated || hits.length > offset + limit,
    queryCandidateCount: extracted.value.candidates.length,
    nextOffset,
  })
}

function narrowByPacketContext(
  index: UnlockedLookupIndex,
  entryIndexes: readonly number[],
  contextPackets: Set<number>,
): { indexes: number[]; usedContext: boolean } {
  if (contextPackets.size === 0) return { indexes: [...entryIndexes], usedContext: false }
  const filtered: number[] = []
  for (const ei of entryIndexes) {
    const occs = index.getOccurrences(ei)
    if (occs.some((o) => o.anonymizedPacketNumber > 0 && contextPackets.has(o.anonymizedPacketNumber))) {
      filtered.push(ei)
    }
  }
  // If context doesn't match any, keep all (context may be unrelated elsewhere in paste).
  if (filtered.length === 0) return { indexes: [...entryIndexes], usedContext: false }
  return { indexes: filtered, usedContext: true }
}

function emitValueHits(
  index: UnlockedLookupIndex,
  cand: Extract<RecoveryQueryCandidate, { kind: 'value' }>,
  entryIndexes: readonly number[],
  usedContext: boolean,
  push: (h: Omit<RecoveryHit, 'hitId'>) => void,
): void {
  if (entryIndexes.length === 0) return

  // Multiple entries for same anonymized mask → ambiguous unless context narrowed to one.
  if (entryIndexes.length > 1) {
    push({
      status: 'ambiguous',
      category: cand.categoryHint === 'unknown' ? 'other' : cand.categoryHint,
      matchKind: 'ambiguous',
      queriedValue: cand.text,
      anonymizedCanonical: cand.text,
      candidateCount: entryIndexes.length,
    })
    return
  }

  const entry = index.getEntry(entryIndexes[0]!)
  if (!entry) return

  if (entry.matchKind === 'ambiguous' || entry.matchKind === 'redacted') {
    // Never resolve ambiguous/redacted without context that uniquely identifies one occurrence.
    if (!usedContext) {
      push({
        status: entry.matchKind,
        category: entry.category,
        matchKind: entry.matchKind,
        queriedValue: cand.text,
        anonymizedCanonical: entry.anonymizedCanonical,
        candidateCount: entry.occurrenceCount,
        entryIndex: entry.entryIndex,
      })
      return
    }
    // With packet context, still only reveal if a single occurrence on that packet.
    const occs = index.getOccurrences(entry.entryIndex)
    // Context already filtered entry; check occurrence uniqueness on context packets is handled upstream.
    // Reveal original only when matchKind was exact OR usedContext uniquely pins one occ of an exact entry.
    // For ambiguous-fixed masks, withhold original even with packet context (policy: never auto-decide).
    push({
      status: entry.matchKind,
      category: entry.category,
      matchKind: entry.matchKind,
      queriedValue: cand.text,
      anonymizedCanonical: entry.anonymizedCanonical,
      anonymizedPacketNumber: occs.find((o) => o.anonymizedPacketNumber > 0)?.anonymizedPacketNumber,
      originalPacketNumber: occs.find((o) => o.anonymizedPacketNumber > 0)?.originalPacketNumber,
      candidateCount: entry.occurrenceCount,
      entryIndex: entry.entryIndex,
    })
    return
  }

  const occs = index.getOccurrences(entry.entryIndex)
  const firstOcc = occs[0]
  push({
    status: 'exact',
    category: entry.category,
    matchKind: 'exact',
    queriedValue: cand.text,
    originalValue: entry.originalCanonical,
    originalWire: entry.originalWire,
    anonymizedCanonical: entry.anonymizedCanonical,
    anonymizedPacketNumber: firstOcc && firstOcc.anonymizedPacketNumber > 0
      ? firstOcc.anonymizedPacketNumber
      : undefined,
    originalPacketNumber: firstOcc?.originalPacketNumber,
    candidateCount: 1,
    entryIndex: entry.entryIndex,
    occurrenceIndex: firstOcc?.occurrenceIndex,
  })
}

