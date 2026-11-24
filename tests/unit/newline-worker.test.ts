/**
 * Stage 1 — CRLF/CR correctness via Detection Worker only.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { DetectionWorkerClient } from '../../src/app/workerClient.ts'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker.ts'
import { importFileAndDetect, importPasteAndDetect } from '../../src/features/import-log/streamImport.ts'
import { detectCanonicalText } from '../../src/features/import-log/detectCanonical.ts'
import { CHUNK_SIZE } from '../../src/features/import-log/chunking.ts'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import { fromTransferableBuffers } from '../../src/engine/packedMatchIndex.ts'
import * as analyzeModule from '../../src/engine/analyze.ts'
import { analyze } from '../../src/engine/analyze.ts'
import {
  createLineAssembler,
  pushBytes,
  takePackedLineEndings,
} from '../../src/features/import-log/streamingDecode.ts'
import {
  applyPackedLineEndings,
  ENDING_CRLF,
} from '../../src/features/export-log/lineEndings.ts'
import {
  buildSessionModel,
  clearSessionModel,
} from '../../src/features/workspace/sessionModel.ts'
import { exportAnonymizedReference } from '../../src/features/export-log/exportCoordinator.ts'
import { getExportPlanSnapshot } from '../../src/features/export-log/replacementSnapshot.ts'

const sessionControllerPath = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../src/app/sessionController.ts',
)

function makeClient(factory?: () => FakeDetectionWorker): DetectionWorkerClient {
  return new DetectionWorkerClient({}, factory ?? (() => new FakeDetectionWorker()))
}

function packedStarts(result: Awaited<ReturnType<typeof importPasteAndDetect>>): number[] {
  const packed = fromTransferableBuffers(result.detection.packedMatches)
  return Array.from(packed.starts)
}

import {
  installInProcessMappingWorkerForTests,
  resetInProcessMappingWorkerForTests,
} from '../helpers/inProcessMappingWorker.ts'

beforeEach(() => {
  installInProcessMappingWorkerForTests()
})

afterEach(() => {
  resetInProcessMappingWorkerForTests()
})

describe('Stage 1 — newline worker path', () => {
  it('sessionController production path does not import sync analyze()', () => {
    const src = readFileSync(sessionControllerPath, 'utf8')
    expect(src).not.toMatch(/from ['"].*analyze\.ts['"]/)
    expect(src).not.toMatch(/\banalyze\s*\(/)
    expect(src).not.toMatch(/detectionForEditor/)
  })

  it('LF/CRLF/CR inputs yield identical canonical detection offsets', async () => {
    const ip = '10.55.66.77'
    const canonical = `peer ${ip} ready\nnext\n`
    const variants = [
      canonical,
      `peer ${ip} ready\r\nnext\r\n`,
      `peer ${ip} ready\rnext\r`,
    ]
    const results: Awaited<ReturnType<typeof importPasteAndDetect>>[] = []
    for (const text of variants) {
      const client = makeClient()
      results.push(
        await importPasteAndDetect(text, client, { chunkBytes: CHUNK_SIZE.minBytes }),
      )
      client.dispose()
    }
    const canonicalText = results[0]!.text
    expect(results.every((r) => r.text === canonicalText)).toBe(true)
    const refStarts = packedStarts(results[0]!)
    for (const r of results.slice(1)) {
      expect(packedStarts(r)).toEqual(refStarts)
    }
  })

  it('custom literal rule parity for CRLF vs LF', async () => {
    const client = makeClient()
    const profile = createDefaultRulesetConfig()
    profile.profile.rules.push({
      id: 'canary-literal',
      name: 'Canary',
      enabled: true,
      kind: 'literal',
      pattern: 'SECRET_CANARY',
      category: 'custom',
      replacement: { kind: 'fixed', value: 'REDACTED' },
    })
    const lf = 'before SECRET_CANARY after\n'
    const crlf = 'before SECRET_CANARY after\r\n'
    const lfResult = await importPasteAndDetect(lf, client, { profile })
    const crlfResult = await importPasteAndDetect(crlf, client, { profile })
    expect(lfResult.text).toBe(crlfResult.text)
    expect(
      lfResult.detection.entities.some((e) => e.originalSample.includes('SECRET')),
    ).toBe(true)
    expect(packedStarts(lfResult)).toEqual(packedStarts(crlfResult))
    client.dispose()
  })

  it('splits CRLF across UTF-8 byte chunks and preserves packed endings', () => {
    const state = createLineAssembler()
    const enc = new TextEncoder()
    pushBytes(state, enc.encode('line-a\r'), false)
    const mid = pushBytes(state, enc.encode('\nline-b\r\n'), false)
    expect(mid.lines.map((l) => l.text)).toEqual(['line-a', 'line-b'])
    expect(mid.lfFragment).toBe('line-a\nline-b\n')
    const fin = pushBytes(state, enc.encode(''), true)
    expect(fin.lines.map((l) => l.text)).toEqual([''])
    const endings = takePackedLineEndings(state)
    expect(endings[0]).toBe(ENDING_CRLF)
    expect(endings[1]).toBe(ENDING_CRLF)
  })

  it('export restores original CRLF from streaming decode map', async () => {
    clearSessionModel()
    const client = makeClient()
    const raw = 'peer 10.9.9.9 ok\r\nsecond line\r\n'
    const result = await importPasteAndDetect(raw, client, { chunkBytes: 8 })
    buildSessionModel({
      text: result.text,
      detection: result.detection,
      fileName: 'crlf.log',
      byteLength: raw.length,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: result.lineEndings,
    })
    const snap = getExportPlanSnapshot()!
    const exported = exportAnonymizedReference(snap)
    expect(exported).toContain('\r\n')
    expect(exported).not.toContain('10.9.9.9')
    expect(applyPackedLineEndings(result.text, result.lineEndings)).toBe(raw)
    client.dispose()
  })

  it('detectCanonicalText auto-restarts after regex watchdog timeout', async () => {
    let workers = 0
    const client = new DetectionWorkerClient({}, () => {
      workers++
      return new FakeDetectionWorker(
        workers === 1 ? { hangOnRuleId: 'evil-regex' } : {},
      )
    })
    const profile = createDefaultRulesetConfig()
    profile.profile.rules.push({
      id: 'evil-regex',
      name: 'Evil',
      enabled: true,
      kind: 'regex',
      pattern: '(a+)+$',
      category: 'custom',
      replacement: { kind: 'generated' },
    })

    const text = '10.7.7.7\n'
    const result = await detectCanonicalText(client, text, { profile })
    expect(result.failedRuleIds).toContain('evil-regex')
    expect(result.entities.some((e) => e.category === 'ip')).toBe(true)
    expect(workers).toBeGreaterThanOrEqual(2)
    client.dispose()
  }, 15_000)

  it('import path never calls sync analyze() even for large CRLF paste', async () => {
    const spy = vi.spyOn(analyzeModule, 'analyze')
    const client = makeClient()
    try {
      const line = `host 10.1.1.1 trace\r\n`
      const text = line.repeat(200_000)
      await importPasteAndDetect(text, client, { chunkBytes: CHUNK_SIZE.defaultBytes })
      expect(spy).not.toHaveBeenCalled()
    } finally {
      spy.mockRestore()
      client.dispose()
    }
  })

  it('reanalyzeWithActiveProfile preserves imported line endings (sessionController contract)', () => {
    const src = readFileSync(sessionControllerPath, 'utf8')
    expect(src).toMatch(/lastLineEndings/)
    expect(src).toMatch(/preservedLineEndings\s*=\s*lastLineEndings/)
    expect(src).toMatch(/lineEndings:\s*preservedLineEndings/)
  })

  it('file import streams CRLF and detects via worker without sync analyze', async () => {
    const spy = vi.spyOn(analyzeModule, 'analyze')
    const client = makeClient()
    try {
      const raw = 'peer 10.8.8.8 via gw\r\n'
      const blob = new Blob([raw], { type: 'text/plain' })
      const file = new File([blob], 'win.log', { type: 'text/plain' })
      const result = await importFileAndDetect(file, client, { chunkBytes: 4 })
      expect(result.text).toBe('peer 10.8.8.8 via gw\n')
      expect(result.lineEndings[0]).toBe(ENDING_CRLF)
      expect(result.detection.entities.some((e) => e.category === 'ip')).toBe(true)
      expect(spy).not.toHaveBeenCalled()
    } finally {
      spy.mockRestore()
      client.dispose()
    }
  })

  it('feeds detection before the complete file has been decoded', async () => {
    let workerChunks = 0
    const client = makeClient(() => new FakeDetectionWorker({
      onInputChunk: () => {
        workerChunks++
      },
    }))
    const firstChunk = `${'plain line\n'.repeat(48_000)}padding\n`
    const raw = `${firstChunk}peer 10.8.8.9 ready\n`
    let appendCalls = 0
    let detectedWhileImporting = false

    try {
      const result = await importFileAndDetect(new Blob([raw]), client, {
        chunkBytes: CHUNK_SIZE.minBytes,
        handlers: {
          onTextAppend: () => {
            appendCalls++
            if (appendCalls > 1 && workerChunks > 0) detectedWhileImporting = true
          },
        },
      })
      expect(appendCalls).toBeGreaterThan(1)
      expect(workerChunks).toBeGreaterThan(1)
      expect(detectedWhileImporting).toBe(true)
      expect(result.detection.entities.some((e) => e.originalSample === '10.8.8.9')).toBe(true)
    } finally {
      client.dispose()
    }
  })

  it('reopens the file stream after a regex timeout without decoding it twice for the editor', async () => {
    let workers = 0
    const client = new DetectionWorkerClient({}, () => {
      workers++
      return new FakeDetectionWorker(
        workers === 1 ? { hangOnRuleId: 'file-evil-regex' } : {},
      )
    })
    const profile = createDefaultRulesetConfig()
    profile.profile.rules.push({
      id: 'file-evil-regex',
      name: 'File evil',
      enabled: true,
      kind: 'regex',
      pattern: '(a+)+$',
      category: 'custom',
      replacement: { kind: 'generated' },
    })
    const raw = 'peer 10.8.8.10 ready\r\n'
    let appended = ''

    try {
      const result = await importFileAndDetect(new Blob([raw]), client, {
        profile,
        handlers: {
          onTextAppend: (fragment) => {
            appended += fragment
          },
        },
      })
      expect(result.text).toBe('peer 10.8.8.10 ready\n')
      expect(appended).toBe(result.text)
      expect(result.detection.failedRuleIds).toContain('file-evil-regex')
      expect(workers).toBeGreaterThanOrEqual(2)
    } finally {
      client.dispose()
    }
  }, 15_000)
})

describe('Stage 1 — reference parity smoke', () => {
  it('worker detection matches reference analyze on canonical LF text', async () => {
    const client = makeClient()
    const text = 'peer 10.16.1.105\r\nuser=disp5\r\n'
    const worker = await importPasteAndDetect(text, client)
    const canonical = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    const ref = analyze(canonical)
    expect(worker.text).toBe(canonical)
    expect(worker.detection.lineCount).toBe(ref.lineCount)
    const packed = fromTransferableBuffers(worker.detection.packedMatches)
    expect(packed.starts.length).toBe(ref.matches.length)
    client.dispose()
  })
})
