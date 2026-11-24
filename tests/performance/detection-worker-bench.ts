/**
 * Krok 3 worker-path chunk-size benchmarks (Node).
 * Profiles: common / maximum / match-stress — adaptive 512 KiB–4 MiB.
 *
 * Usage: npm run bench:detection-worker
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { DetectionSession } from '../../src/workers/detectionSession.ts'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import {
  CHUNK_SIZE,
  splitPasteText,
} from '../../src/features/import-log/chunking.ts'
import {
  adaptChunkSizeFromBenchmark,
  setRecommendedChunkBytes,
  getRecommendedChunkBytes,
} from '../../src/features/import-log/chunkSizing.ts'

const here = path.dirname(fileURLToPath(import.meta.url))
const outDir = path.join(here, 'results')

type ProfileName = 'common' | 'maximum' | 'match-stress'

function generateProfile(name: ProfileName): string {
  const lines: string[] = []
  if (name === 'common') {
    for (let i = 0; i < 8_000; i++) {
      lines.push(
        `2026-08-10 06:00:00.${String(i).padStart(3, '0')} INFO peer=10.${i % 200}.${i % 50}.${i % 250} user=disp${(i % 24) + 1} host=node-${i % 40}.corp.example`,
      )
    }
  } else if (name === 'maximum') {
    for (let i = 0; i < 25_000; i++) {
      lines.push(
        `L${i} ip=10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255} sip:97${String(i).padStart(7, '0')}@10.1.1.1 GRP_TEST_${i % 9} MP_X${i % 20}`,
      )
    }
  } else {
    for (let i = 0; i < 6_000; i++) {
      lines.push(
        `disp${(i % 24) + 1} 10.16.1.${i % 200} ldap-pra.corp.example sip:97205${String(1000 + (i % 900)).slice(0, 4)}@10.37.63.169 user=Person Name${i % 10} tenant 'Tenant ${i % 5}'`,
      )
    }
  }
  return lines.join('\n') + '\n'
}

function runSession(
  text: string,
  chunkBytes: number,
): { elapsedMs: number; matches: number; lines: number; chunks: number } {
  const t0 = performance.now()
  const session = new DetectionSession({
    onProgress: () => {},
    onRuleStarted: () => {},
    onHeartbeat: () => {},
  })
  session.start('bench', createDefaultRulesetConfig())
  const slices = splitPasteText(text, chunkBytes)
  for (const s of slices) {
    session.pushTextChunk(s.text, s.final)
  }
  const out = session.finalizeDetection()
  return {
    elapsedMs: performance.now() - t0,
    matches: out.packedMatches.count,
    lines: out.lineCount,
    chunks: slices.length,
  }
}

function main(): void {
  fs.mkdirSync(outDir, { recursive: true })
  const sizes = [CHUNK_SIZE.minBytes, CHUNK_SIZE.defaultBytes, CHUNK_SIZE.maxBytes]
  const report: Record<string, unknown> = {
    generatedAt: new Date().toISOString(),
    sizes,
    profiles: {} as Record<string, unknown>,
  }

  setRecommendedChunkBytes(CHUNK_SIZE.defaultBytes)

  for (const name of ['common', 'maximum', 'match-stress'] as ProfileName[]) {
    const text = generateProfile(name)
    const bytes = new TextEncoder().encode(text).byteLength
    const perSize: Record<string, unknown> = { inputBytes: bytes, inputChars: text.length }
    let best = { chunkBytes: CHUNK_SIZE.defaultBytes, elapsedMs: Number.POSITIVE_INFINITY }

    for (const chunkBytes of sizes) {
      const result = runSession(text, chunkBytes)
      perSize[`chunk_${chunkBytes}`] = result
      if (result.elapsedMs < best.elapsedMs) {
        best = { chunkBytes, elapsedMs: result.elapsedMs }
      }
      adaptChunkSizeFromBenchmark({
        chunkBytes,
        elapsedMs: result.elapsedMs,
        processedBytes: bytes,
      })
    }

    perSize.bestChunkBytes = best.chunkBytes
    perSize.recommendedAfter = getRecommendedChunkBytes()
    ;(report.profiles as Record<string, unknown>)[name] = perSize
    console.log(
      `${name}: best chunk=${best.chunkBytes} (${best.elapsedMs.toFixed(1)} ms), recommended=${getRecommendedChunkBytes()}`,
    )
  }

  // Final recommendation clamped into architecture range.
  const recommended = getRecommendedChunkBytes()
  report.finalRecommendedChunkBytes = recommended
  report.withinRange =
    recommended >= CHUNK_SIZE.minBytes && recommended <= CHUNK_SIZE.maxBytes

  const jsonPath = path.join(outDir, 'detection-worker-bench.json')
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2))
  console.log('wrote', jsonPath)
}

main()
