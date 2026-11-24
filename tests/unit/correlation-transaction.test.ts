import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient, getSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import {
  addCorrelationSource,
  clearCorrelationSession,
  createTextSourceAdapter,
  getCorrelationSource,
  getPublishedCorrelationManifest,
  isPublishedManifestStale,
  registerSourceAdapter,
  removeCorrelationSource,
  resetCorrelationAdaptersForTests,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import { useAppStore } from '../../src/app/store'
import type { SourceAdapter } from '../../src/correlation/types'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Stage 24 correlation transactions', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
  })

  it('adding compatible source preserves byte-identical existing plans', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'a', kind: SK.Text, file: textFile('a.log', 'host 10.0.0.1\n') },
    ])
    await runCorrelationSession()
    const planBefore = JSON.stringify(getCorrelationSource('a')?.plan)

    const added = await addCorrelationSource({
      sourceId: 'b',
      kind: SK.Text,
      file: textFile('b.log', 'also 10.0.0.1 and 10.0.0.2\n'),
    })
    expect('ok' in added && added.ok).toBe(true)

    const planAfter = JSON.stringify(getCorrelationSource('a')?.plan)
    expect(planAfter).toBe(planBefore)
  })

  it('failed staging of new source leaves mappingRevision unchanged', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'base', kind: SK.Text, file: textFile('base.log', '10.0.0.3\n') },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)
    if (!('ok' in processed) || !processed.ok) return

    const revisionBefore = processed.mappingRevision
    const manifestBefore = getPublishedCorrelationManifest()

    const failingAdapter: SourceAdapter = {
      kind: SK.Text,
      probe: () => ({ ok: true, kind: SK.Text }),
      preflight: async (file) => ({ ok: true, byteLength: file.size, kind: SK.Text }),
      discover: async () => {
        throw new Error('parser boom')
      },
      buildPlan: async () => {
        throw new Error('unreachable')
      },
    }
    registerSourceAdapter(failingAdapter)

    const failed = await addCorrelationSource({
      sourceId: 'bad',
      kind: SK.Text,
      file: textFile('bad.log', 'x\n'),
    })
    expect('ok' in failed).toBe(false)

    expect(getSharedMappingClient().getPublishedRevision()).toBe(revisionBefore)
    expect(getPublishedCorrelationManifest()).toEqual(manifestBefore)
    expect(getCorrelationSource('bad')).toBeNull()
  })

  it('removing source retains alias and drops unused plaintext', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'keep', kind: SK.Text, file: textFile('keep.log', '10.0.0.8\n') },
      { sourceId: 'drop', kind: SK.Text, file: textFile('drop.log', '10.0.0.8\n') },
    ])
    await runCorrelationSession()

    const client = getSharedMappingClient()
    const snapBefore = client.getPublishedSnapshot()
    const shared = snapBefore?.entries.find((e) => e.canonical === '10.0.0.8')
    expect(shared?.alias).toBeTruthy()

    const keepPlan = JSON.stringify(getCorrelationSource('keep')?.plan)

    const removed = await removeCorrelationSource('drop')
    expect('ok' in removed && removed.ok).toBe(true)
    expect(removed.aliasRetained).toBe(true)

    const lookup = await client.lookupByAlias(shared!.alias)
    expect(lookup.length).toBeGreaterThan(0)

    const planAfter = JSON.stringify(getCorrelationSource('keep')?.plan)
    expect(planAfter).toBe(keepPlan)
    expect(getCorrelationSource('drop')).toBeNull()
  })

  it('manifest snapshot is stale when it no longer matches session', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'only', kind: SK.Text, file: textFile('only.log', '10.0.0.4\n') },
    ])
    await runCorrelationSession()
    const oldManifest = getPublishedCorrelationManifest()
    expect(oldManifest).not.toBeNull()
    if (!oldManifest) return

    await removeCorrelationSource('only')
    const { isCorrelationManifestStale } = await import('../../src/correlation/correlationManifest')
    expect(isCorrelationManifestStale(oldManifest)).toBe(true)
    expect(isPublishedManifestStale()).toBe(false)
  })
})
