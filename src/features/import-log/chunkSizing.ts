/**
 * Adaptive detection/import chunk size (ARCHITECTURE §8 / Krok 3).
 * Benchmarks may move the value within [512 KiB, 4 MiB]; default 1 MiB.
 */

import { CHUNK_SIZE } from './chunking.ts'

let recommendedChunkBytes = CHUNK_SIZE.defaultBytes

export function getRecommendedChunkBytes(): number {
  return recommendedChunkBytes
}

export function setRecommendedChunkBytes(bytes: number): number {
  recommendedChunkBytes = Math.max(
    CHUNK_SIZE.minBytes,
    Math.min(CHUNK_SIZE.maxBytes, Math.floor(bytes)),
  )
  return recommendedChunkBytes
}

/**
 * Given measured ms/chunk for a profile, nudge toward faster throughput
 * without exceeding max or dropping below min.
 */
export function adaptChunkSizeFromBenchmark(input: {
  chunkBytes: number
  elapsedMs: number
  processedBytes: number
  /** Target wall time per chunk on main/worker handoff. */
  targetChunkMs?: number
}): number {
  const targetMs = input.targetChunkMs ?? 40
  if (input.elapsedMs <= 0 || input.processedBytes <= 0) {
    return setRecommendedChunkBytes(input.chunkBytes)
  }
  const msPerByte = input.elapsedMs / input.processedBytes
  const ideal = targetMs / msPerByte
  // Blend toward ideal; avoid wild jumps.
  const blended = input.chunkBytes * 0.5 + ideal * 0.5
  return setRecommendedChunkBytes(blended)
}
