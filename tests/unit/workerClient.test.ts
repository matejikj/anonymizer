import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import {
  DetectionWorkerClient,
  MAX_IN_FLIGHT_CHUNKS,
  WATCHDOG_MS,
} from '../../src/app/workerClient.ts'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker.ts'
import {
  installInProcessMappingWorkerForTests,
  resetInProcessMappingWorkerForTests,
} from '../helpers/inProcessMappingWorker.ts'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema.ts'
import { WORKER_ERROR } from '../../src/workers/protocol.ts'
import { importPasteAndDetect } from '../../src/features/import-log/streamImport.ts'
import { CHUNK_SIZE } from '../../src/features/import-log/chunking.ts'

describe('DetectionWorkerClient', () => {
  beforeEach(() => {
    installInProcessMappingWorkerForTests()
  })

  afterEach(() => {
    resetInProcessMappingWorkerForTests()
  })

  it('detects via fake worker with backpressure slots', async () => {
    let created = 0
    const client = new DetectionWorkerClient({}, () => {
      created++
      return new FakeDetectionWorker({ acceptDelayMs: 5 })
    })
    const text = 'host 10.2.2.2 and disp3\n'
    const result = await importPasteAndDetect(text, client, {
      chunkBytes: CHUNK_SIZE.minBytes,
    })
    expect(result.detection.lineCount).toBeGreaterThanOrEqual(1)
    expect(result.detection.entities.some((e) => e.category === 'ip')).toBe(true)
    expect(created).toBeGreaterThanOrEqual(1)
    expect(MAX_IN_FLIGHT_CHUNKS).toBe(2)
    client.dispose()
  })

  it('ignores stale responses after cancel / new generation', async () => {
    const client = new DetectionWorkerClient({}, () => new FakeDetectionWorker())
    const id1 = client.begin(createDefaultRulesetConfig())
    const stalePromise = client.waitForResult(id1).then(
      (v) => ({ ok: true as const, v }),
      (e: Error) => ({ ok: false as const, e }),
    )
    client.cancel()
    const settled = await stalePromise
    expect(settled.ok).toBe(false)
    if (!settled.ok) expect(settled.e.message).toMatch(/zrušena/i)

    const text = '10.3.3.3\n'
    const result = await importPasteAndDetect(text, client, {
      chunkBytes: CHUNK_SIZE.minBytes,
    })
    expect(result.detection.requestId).not.toBe(id1)
    client.dispose()
  })

  it('watchdog terminates hung regex rule and reports timeout', async () => {
    let hang = true
    const client = new DetectionWorkerClient({}, () =>
      new FakeDetectionWorker(hang ? { hangOnRuleId: 'evil-regex' } : {}),
    )
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

    const requestId = client.begin(profile)
    const resultPromise = client.waitForResult(requestId).then(
      (v) => ({ ok: true as const, v }),
      (e: Error & { code?: string; ruleId?: string }) => ({ ok: false as const, e }),
    )

    await client.sendChunk(requestId, {
      sequence: 0,
      text: 'aaaaaaaaaaaaaaaa!\n',
      final: true,
    })

    await new Promise((r) => setTimeout(r, WATCHDOG_MS + 400))

    const settled = await resultPromise
    expect(settled.ok).toBe(false)
    if (!settled.ok) {
      expect(settled.e).toMatchObject({
        code: WORKER_ERROR.regexTimeout,
        ruleId: 'evil-regex',
      })
    }
    expect(client.getFailedRuleIds()).toContain('evil-regex')

    hang = false
    const ok = await importPasteAndDetect('10.4.4.4\n', client, {
      profile: {
        ...profile,
        profile: {
          ...profile.profile,
          rules: profile.profile.rules.map((r) =>
            r.id === 'evil-regex' ? { ...r, enabled: false } : r,
          ),
        },
      },
      chunkBytes: CHUNK_SIZE.minBytes,
    })
    expect(ok.detection.entities.some((e) => e.category === 'ip')).toBe(true)
    client.dispose()
  }, 15_000)
})
