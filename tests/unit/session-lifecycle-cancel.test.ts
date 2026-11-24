/**
 * Stage 5 integration — cancel paths and mapping cleanup after lifecycle dispose.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import {
  cancelActiveOperation,
  disposeActiveSession,
  enterResolveOnly,
  getActiveSessionKind,
  getLifecycleGeneration,
  isLifecycleGenerationCurrent,
  noteActiveSessionKind,
  resetApplication,
  resetLifecycleCoordinatorForTests,
  startCorrelationSession,
} from '../../src/app/sessionLifecycleCoordinator'
import { resetDisposeGuardForTests } from '../../src/app/sessionLifecycleDispose'
import { useAppStore } from '../../src/app/store'
import { clearSessionModel } from '../../src/features/workspace/sessionModel'
import { clearStagingItems, getStagingItems, replaceStagingItems } from '../../src/correlation/import/stagingModel'
import { clearResolveOnlyModel, getResolveOnlyPayload, setResolveOnlyPayload } from '../../src/features/resolve-only/resolveOnlyModel'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import {
  getSharedMappingClient,
  resetSharedMappingClient,
  setSharedMappingClientForTests,
} from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import type { MappingBundlePayload } from '../../src/mapping/bundle/types'

function readyStaging(id: string, name: string) {
  return {
    id,
    fileName: name,
    kind: SK.Text,
    status: 'ready' as const,
    byteLength: 4,
    profileLabel: 'default',
    file: new File(['line'], name, { type: 'text/plain' }),
  }
}

const emptyBundle: MappingBundlePayload = {
  sessionId: 's',
  canonicalizationVersion: 1,
  mappingRevision: 1,
  sources: [],
  entries: [],
}

describe('Stage 5 lifecycle cancel / mapping integration', () => {
  beforeEach(() => {
    resetLifecycleCoordinatorForTests()
    resetDisposeGuardForTests()
    clearSessionModel()
    clearStagingItems()
    clearResolveOnlyModel()
    resetSharedMappingClient()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    disposeActiveSession()
    resetLifecycleCoordinatorForTests()
    resetDisposeGuardForTests()
    resetSharedMappingClient()
  })

  it('cancel during correlation processing keeps staging and clears pending mapping snapshot', async () => {
    replaceStagingItems([readyStaging('a', 'a.log'), readyStaging('b', 'b.log')])
    startCorrelationSession()
    await getSharedMappingClient().resolve('g', 'a', [
      { category: 'ip', canonical: '10.1.1.1', constraint: { kind: 'ipv4-wire' } },
    ])
    expect(getSharedMappingClient().getPublishedSnapshot()).not.toBeNull()

    useAppStore.getState().setPhase('correlation-processing')
    const before = getLifecycleGeneration()
    cancelActiveOperation()
    expect(isLifecycleGenerationCurrent(before)).toBe(false)
    expect(getStagingItems().length).toBe(2)
    expect(getActiveSessionKind()).toBe('correlation')
    expect(getSharedMappingClient().getPublishedSnapshot()).toBeNull()
  })

  it('cancel from text kind returns empty and invalidates generation', () => {
    noteActiveSessionKind('text')
    useAppStore.getState().setPhase('importing')
    const token = getLifecycleGeneration()
    cancelActiveOperation()
    expect(isLifecycleGenerationCurrent(token)).toBe(false)
    expect(useAppStore.getState().phase).toBe('empty')
    expect(useAppStore.getState().importProgress.phase).toBe('cancelled')
    expect(getActiveSessionKind()).toBe('none')
  })

  it('worker resolve then dispose leaves no pending mapping staging', async () => {
    noteActiveSessionKind('text')
    const client = getSharedMappingClient()
    await client.resolve('g', 's', [
      { category: 'ip', canonical: '8.8.8.8', constraint: { kind: 'ipv4-wire' } },
    ])
    expect(client.getPublishedRevision()).toBeGreaterThan(0)
    disposeActiveSession()
    expect(getSharedMappingClient().getPublishedRevision()).toBe(0)
    expect(getSharedMappingClient().getPublishedSnapshot()).toBeNull()
  })

  it('enterResolveOnly imported preserves payload after disposing prior text kind', () => {
    noteActiveSessionKind('text')
    setResolveOnlyPayload(emptyBundle, 'import.bin')
    enterResolveOnly({ mode: 'imported' })
    expect(getResolveOnlyPayload()).not.toBeNull()
    expect(getActiveSessionKind()).toBe('resolve-only')
    expect(useAppStore.getState().phase).toBe('resolve-only')
  })

  it('resetApplication after resolve-only clears decrypted payload', () => {
    enterResolveOnly()
    setResolveOnlyPayload(emptyBundle, 'x.bin')
    resetApplication()
    expect(getResolveOnlyPayload()).toBeNull()
    expect(getActiveSessionKind()).toBe('none')
  })
})
