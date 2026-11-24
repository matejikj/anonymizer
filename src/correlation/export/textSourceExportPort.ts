/**
 * Text source export from correlation plan (Stage 29).
 */

import type { TextSourceDiscovery, TextSourcePlan } from '../types'
import { readFileByteChunks } from '../../features/import-log/chunking'
import { getRecommendedChunkBytes } from '../../features/import-log/chunkSizing'
import {
  createLineAssembler,
  pushBytes,
  takePackedLineEndings,
} from '../../features/import-log/streamingDecode'
import {
  ExportCancelledError,
  runChunkedExportFromSnapshot,
  type ExportProgress,
  type ExportResult,
} from '../../features/export-log/exportCoordinator'
import type { ExportPlanSnapshot } from '../../features/export-log/replacementSnapshot'
import { patchEntitySummariesFromSnapshot } from '../../engine/entityRegistry'
import { getSharedMappingClient } from '../../mapping/sharedMappingClient'
import type { Entity } from '../../domain/types'

export function buildTextExportSnapshot(
  plan: TextSourcePlan,
  discovery: TextSourceDiscovery,
  original: string,
): ExportPlanSnapshot {
  const snapshot = getSharedMappingClient().getPublishedSnapshot()
  if (!snapshot) {
    throw new Error('Chybí publikovaný mapping snapshot pro export')
  }
  const summaries = patchEntitySummariesFromSnapshot(discovery.detection.entities, snapshot)
  const entities: Entity[] = summaries.map((s) => ({
    key: s.key,
    category: s.category,
    originalSample: s.originalSample,
    normalized: s.normalized,
    replacement: s.replacement,
    occurrenceCount: s.occurrenceCount,
    occurrenceIndexes: new Uint32Array(0),
    enabled: s.enabled,
    source: s.source,
    sourceId: s.sourceId,
    createdOrder: s.createdOrder,
  }))

  return {
    plan: plan.plan,
    packed: plan.packed,
    entities,
    original,
    lineEndings: discovery.lineEndings,
    planRevision: plan.mappingRevision,
    fileName: discovery.fileName,
    mode: original.length > 2_000_000 ? 'large' : 'common',
    byteLength: discovery.byteLength,
  }
}

export async function loadTextFileForExport(file: File): Promise<{ text: string; lineEndings: Uint8Array }> {
  const assembler = createLineAssembler()
  const lfParts: string[] = []
  for await (const chunk of readFileByteChunks(file, getRecommendedChunkBytes())) {
    const view = new Uint8Array(chunk.bytes, chunk.byteOffset, chunk.byteLength)
    const { lfFragment } = pushBytes(assembler, view, chunk.final)
    if (lfFragment.length > 0) lfParts.push(lfFragment)
  }
  return { text: lfParts.join(''), lineEndings: takePackedLineEndings(assembler) }
}

export async function exportTextSourcePlan(input: {
  plan: TextSourcePlan
  discovery: TextSourceDiscovery
  original: string
  outputFileName: string
  signal?: AbortSignal
  onProgress?: (p: ExportProgress) => void
  forceMainThread?: boolean
}): Promise<ExportResult> {
  const snapshot = buildTextExportSnapshot(input.plan, input.discovery, input.original)
  try {
    return await runChunkedExportFromSnapshot(snapshot, {
      fileName: input.outputFileName,
      signal: input.signal,
      onProgress: input.onProgress,
      forceMainThread: input.forceMainThread,
    })
  } catch (err) {
    if (err instanceof ExportCancelledError) throw err
    throw err
  }
}
