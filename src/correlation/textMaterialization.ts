/**
 * Lazy text materialization — at most one CodeMirror-sized string cached (Stage 24).
 */

import { discoverTextFile } from './textDiscovery'
import { DetectionWorkerClient } from '../app/workerClient'
import { getActiveProfile } from '../features/rules/activeProfile'
import { readFileByteChunks } from '../features/import-log/chunking'
import { getRecommendedChunkBytes } from '../features/import-log/chunkSizing'
import {
  createLineAssembler,
  pushBytes,
  takePackedLineEndings,
} from '../features/import-log/streamingDecode'

export interface MaterializedText {
  readonly sourceId: string
  readonly text: string
  readonly lineEndings: Uint8Array
}

let cached: MaterializedText | null = null

async function decodeFileToCanonicalText(file: File): Promise<{ text: string; lineEndings: Uint8Array }> {
  const assembler = createLineAssembler()
  const parts: string[] = []
  for await (const chunk of readFileByteChunks(file, getRecommendedChunkBytes())) {
    const view = new Uint8Array(chunk.bytes, chunk.byteOffset, chunk.byteLength)
    const { lfFragment } = pushBytes(assembler, view, chunk.final)
    if (lfFragment.length > 0) parts.push(lfFragment)
  }
  return { text: parts.join(''), lineEndings: takePackedLineEndings(assembler) }
}

export function getMaterializedTextSourceId(): string | null {
  return cached?.sourceId ?? null
}

export function countMaterializedTextSources(): number {
  return cached ? 1 : 0
}

export function releaseTextMaterialization(): void {
  cached = null
}

export async function materializeTextFileForReview(sourceId: string, file: File): Promise<MaterializedText> {
  if (cached?.sourceId === sourceId) {
    return cached
  }
  releaseTextMaterialization()
  const decoded = await decodeFileToCanonicalText(file)
  cached = {
    sourceId,
    text: decoded.text,
    lineEndings: decoded.lineEndings,
  }
  return cached
}

export async function materializeTextForSource(
  sourceId: string,
  file: File,
  deps?: { createDetectionClient?: () => DetectionWorkerClient },
): Promise<MaterializedText> {
  if (cached?.sourceId === sourceId) {
    return cached
  }
  releaseTextMaterialization()

  const client = deps?.createDetectionClient?.() ?? new DetectionWorkerClient()
  try {
    const discovered = await discoverTextFile({
      file,
      sourceId,
      client,
      profile: getActiveProfile(),
      retainText: true,
    })
    cached = {
      sourceId,
      text: discovered.text,
      lineEndings: discovered.lineEndings,
    }
    return cached
  } finally {
    client.dispose()
  }
}

export function selectTextSourceForPreview(sourceId: string | null): void {
  if (sourceId === null || cached?.sourceId === sourceId) return
  releaseTextMaterialization()
}
