/**
 * Text discovery without mapping resolve (Stage 23 discover phase).
 */

import type { RulesetConfig } from '../domain/configSchema'
import { createDefaultRulesetConfig } from '../domain/configSchema'
import {
  DetectionWorkerClient,
  type DetectionResult,
} from '../app/workerClient'
import { canonicalizeTextIdentity, defaultTextWireConstraint } from '../mapping/textCanonical'
import type { CanonicalIdentity } from '../mapping/types'
import { correlationRegistryKey } from '../mapping/crossFormat/identityKey'
import { fromTransferableBuffers, type PackedMatchBuffers } from '../engine/packedMatchIndex'
import { getRecommendedChunkBytes } from '../features/import-log/chunkSizing'
import { ImportCancelledError } from '../features/import-log/streamImport'
import {
  createLineAssembler,
  pushBytes,
  takePackedLineEndings,
} from '../features/import-log/streamingDecode'
import { INPUT_LIMITS } from '../features/import-log/inputLimits'
import { detectFileBytes } from '../features/import-log/detectCanonical'

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ImportCancelledError()
}

/** First occurrence (line, start, end) per entity, keyed by its index in `entities`. */
function firstOccurrenceByEntityIndex(
  packedMatches: PackedMatchBuffers,
): Map<number, { line: number; start: number; end: number }> {
  const packed = fromTransferableBuffers(packedMatches)
  const result = new Map<number, { line: number; start: number; end: number }>()
  for (let i = 0; i < packed.starts.length; i++) {
    const entityIndex = packed.entityIndexes[i]!
    if (result.has(entityIndex)) continue
    const start = packed.starts[i]!
    result.set(entityIndex, { line: packed.lines[i]!, start, end: start + packed.lengths[i]! })
  }
  return result
}

export function identitiesFromDetectionEntities(
  entities: DetectionResult['entities'],
  sourceId: string,
  packedMatches: DetectionResult['packedMatches'],
): CanonicalIdentity[] {
  const firstOccurrence = firstOccurrenceByEntityIndex(packedMatches)
  const seen = new Set<string>()
  const out: CanonicalIdentity[] = []
  entities.forEach((e, entityIndex) => {
    const canonical = canonicalizeTextIdentity(e.category, e.originalSample)
    if (!canonical) return
    const occ = firstOccurrence.get(entityIndex)
    const id: CanonicalIdentity = {
      category: e.category,
      canonical,
      constraint: defaultTextWireConstraint(e.category, canonical, e.originalSample),
      originalSpelling: e.originalSample,
      source: { detectorId: e.sourceId },
      occurrence: {
        kind: 'text',
        sourceId,
        line: occ?.line ?? 1,
        start: occ?.start ?? 0,
        end: occ?.end ?? e.originalSample.length,
      },
    }
    const key = correlationRegistryKey(id)
    if (seen.has(key)) return
    seen.add(key)
    out.push(id)
  })
  return out
}

export async function discoverTextFile(input: {
  file: File
  sourceId: string
  client: DetectionWorkerClient
  profile?: RulesetConfig
  signal?: AbortSignal
  onProgress?: (phase: string, done: number, total: number) => void
  /** When false (default), full text is not retained after detection (Stage 24 bounded memory). */
  retainText?: boolean
}): Promise<{
  text: string
  lineEndings: Uint8Array
  detection: DetectionResult
  identities: CanonicalIdentity[]
}> {
  if (input.file.size > INPUT_LIMITS.fileMaxBytes) {
    throw new Error(`File exceeds ${INPUT_LIMITS.fileMaxBytes} bytes`)
  }

  const profile = input.profile ?? createDefaultRulesetConfig()
  const assembler = createLineAssembler()
  const lfParts: string[] = []
  let processedBytes = 0

  const detection = await detectFileBytes(input.client, input.file, {
    profile,
    chunkBytes: getRecommendedChunkBytes(),
    signal: input.signal,
    sourceId: input.sourceId,
    resolveMappings: false,
    onFirstPassChunk: (view, final) => {
      throwIfAborted(input.signal)
      const { lfFragment } = pushBytes(assembler, view, final)
      if (input.retainText && lfFragment.length > 0) lfParts.push(lfFragment)
      processedBytes += view.byteLength
      input.onProgress?.('loading', processedBytes, input.file.size)
      if (assembler.processedLines > INPUT_LIMITS.fileMaxLines) {
        input.client.cancel()
        throw new Error(`File exceeds ${INPUT_LIMITS.fileMaxLines} lines`)
      }
    },
    onProgress: (ev) => {
      if (processedBytes >= input.file.size) {
        input.onProgress?.('analyzing', input.file.size, input.file.size)
      }
      void ev
    },
  })
  const text = input.retainText ? lfParts.join('') : ''
  const lineEndings = takePackedLineEndings(assembler)

  const identities = identitiesFromDetectionEntities(detection.entities, input.sourceId, detection.packedMatches)
  return {
    text,
    lineEndings,
    detection,
    identities,
  }
}
