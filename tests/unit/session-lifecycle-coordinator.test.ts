/**
 * Stage 5 — SessionLifecycleCoordinator: transitions, idempotent dispose, generation tokens.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import {
  cancelActiveOperation,
  disposeActiveSession,
  enterResolveOnly,
  getActiveSessionKind,
  getLifecycleGeneration,
  getLifecycleInventory,
  isLifecycleGenerationCurrent,
  isLifecycleTransitionAllowed,
  noteActiveSessionKind,
  resetApplication,
  resetLifecycleCoordinatorForTests,
  startCorrelationSession,
  ZUSTAND_FORBIDDEN_PAYLOADS,
} from '../../src/app/sessionLifecycleCoordinator'
import { resetDisposeGuardForTests } from '../../src/app/sessionLifecycleDispose'
import { requiresExclusiveDispose } from '../../src/app/sessionLifecycleInventory'
import { useAppStore } from '../../src/app/store'
import { buildSessionModel, clearSessionModel, getSessionModel } from '../../src/features/workspace/sessionModel'
import { getPcapSession } from '../../src/pcap/ui/pcapSession'
import { getStagingItems, replaceStagingItems, clearStagingItems } from '../../src/correlation/import/stagingModel'
import { getCorrelationUiPhase } from '../../src/correlation/correlationPhaseModel'
import {
  setResolveOnlyPayload,
  getResolveOnlyPayload,
  clearResolveOnlyModel,
} from '../../src/features/resolve-only/resolveOnlyModel'
import { releaseMappingSession } from '../../src/mapping/sessionLifecycle'
import { getSharedMappingClient, resetSharedMappingClient, setSharedMappingClientForTests } from '../../src/mapping/sharedMappingClient'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import type { MappingBundlePayload } from '../../src/mapping/bundle/types'
import type { DetectionResult } from '../../src/app/workerClient'

const EMPTY_PACKED = {
  starts: new Uint32Array(0),
  lengths: new Uint32Array(0),
  lines: new Uint32Array(0),
  entityIndexes: new Uint32Array(0),
  flags: new Uint8Array(0),
}

function minimalDetection(): DetectionResult {
  return {
    requestId: 'req-1',
    packedMatches: EMPTY_PACKED,
    entities: [],
    lineCount: 1,
    failedRuleIds: [],
  }
}

function emptyBundle(): MappingBundlePayload {
  return {
    sessionId: 's',
    canonicalizationVersion: 1,
    mappingRevision: 1,
    sources: [],
    entries: [],
  }
}

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

describe('Stage 5 SessionLifecycleCoordinator', () => {
  beforeEach(() => {
    resetLifecycleCoordinatorForTests()
    resetDisposeGuardForTests()
    clearSessionModel()
    clearStagingItems()
    clearResolveOnlyModel()
    releaseMappingSession()
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

  it('documents inventoru long-lived resources with neverInZustand', () => {
    const inv = getLifecycleInventory()
    expect(inv.length).toBeGreaterThanOrEqual(10)
    expect(inv.every((r) => r.idempotent === true && r.neverInZustand === true)).toBe(true)
    expect(ZUSTAND_FORBIDDEN_PAYLOADS).toEqual(
      expect.arrayContaining(['log-text', 'packet-bytes', 'mapping-registry', 'decrypted-bundle']),
    )
  })

  it('allows transitions and requires exclusive dispose across kinds', () => {
    expect(isLifecycleTransitionAllowed('none', 'text')).toBe(true)
    expect(isLifecycleTransitionAllowed('text', 'pcap')).toBe(true)
    expect(isLifecycleTransitionAllowed('pcap', 'none')).toBe(true)
    expect(requiresExclusiveDispose('text', 'pcap')).toBe(true)
    expect(requiresExclusiveDispose('text', 'text')).toBe(false)
    expect(requiresExclusiveDispose('none', 'correlation')).toBe(false)
  })

  it('bumps generation and rejects stale tokens after dispose', () => {
    noteActiveSessionKind('text')
    const token = getLifecycleGeneration()
    expect(isLifecycleGenerationCurrent(token)).toBe(true)
    disposeActiveSession()
    expect(isLifecycleGenerationCurrent(token)).toBe(false)
    expect(getActiveSessionKind()).toBe('none')
    expect(getLifecycleGeneration()).toBeGreaterThan(token)
  })

  it('disposeActiveSession is idempotent', () => {
    noteActiveSessionKind('text')
    buildSessionModel({
      text: 'hi\n',
      detection: minimalDetection(),
      fileName: 'a.log',
      byteLength: 3,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: new Uint8Array([1]),
    })
    expect(getSessionModel()).not.toBeNull()
    disposeActiveSession()
    disposeActiveSession()
    resetApplication()
    expect(getSessionModel()).toBeNull()
    expect(getPcapSession()).toBeNull()
    expect(getActiveSessionKind()).toBe('none')
    expect(useAppStore.getState().phase).toBe('empty')
  })

  it('startCorrelationSession projects staging UI and cancel during processing keeps staging', () => {
    replaceStagingItems([readyStaging('s1', 'a.log'), readyStaging('s2', 'b.log')])
    startCorrelationSession()
    expect(getActiveSessionKind()).toBe('correlation')
    expect(useAppStore.getState().phase).toBe('correlation-staging')
    expect(getCorrelationUiPhase().kind).toBe('staging')
    expect(getStagingItems().length).toBe(2)

    useAppStore.getState().setPhase('correlation-processing')
    cancelActiveOperation()
    expect(getActiveSessionKind()).toBe('correlation')
    expect(useAppStore.getState().phase).toBe('correlation-staging')
    expect(getStagingItems().length).toBe(2)

    disposeActiveSession()
    expect(getStagingItems().length).toBe(0)
    expect(getActiveSessionKind()).toBe('none')
  })

  it('enterResolveOnly wizard then dispose clears decrypted payload', () => {
    enterResolveOnly()
    expect(getActiveSessionKind()).toBe('resolve-only')
    expect(useAppStore.getState().phase).toBe('resolve-only')

    setResolveOnlyPayload(emptyBundle(), 'm.bin')
    expect(getResolveOnlyPayload()).not.toBeNull()

    disposeActiveSession()
    expect(getResolveOnlyPayload()).toBeNull()
    expect(getActiveSessionKind()).toBe('none')
  })

  it('resetApplication (ErrorBoundary path) clears session, staging, mapping and resolve payload', async () => {
    noteActiveSessionKind('text')
    buildSessionModel({
      text: 'secret 10.0.0.1\n',
      detection: minimalDetection(),
      fileName: 'sec.log',
      byteLength: 16,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: new Uint8Array([1]),
    })
    replaceStagingItems([readyStaging('s1', 'x.log')])
    const client = getSharedMappingClient()
    await client.resolve('gen', 'source', [
      {
        category: 'ip',
        canonical: '10.0.0.1',
        constraint: { kind: 'ipv4-wire' },
      },
    ])
    expect(client.getPublishedSnapshot()).not.toBeNull()
    setResolveOnlyPayload(emptyBundle(), 'b.bin')

    resetApplication()

    expect(getSessionModel()).toBeNull()
    expect(getStagingItems().length).toBe(0)
    expect(getResolveOnlyPayload()).toBeNull()
    expect(getSharedMappingClient().getPublishedSnapshot()).toBeNull()
    expect(useAppStore.getState().phase).toBe('empty')
    expect(getActiveSessionKind()).toBe('none')
  })

  it('Zustand shell state has no forbidden payload keys', () => {
    const state = useAppStore.getState() as Record<string, unknown>
    for (const key of ZUSTAND_FORBIDDEN_PAYLOADS) {
      expect(Object.prototype.hasOwnProperty.call(state, key)).toBe(false)
    }
    expect(state).not.toHaveProperty('logText')
    expect(state).not.toHaveProperty('packetBytes')
    expect(state).not.toHaveProperty('mappingRegistry')
    expect(state).not.toHaveProperty('decryptedBundle')
  })

  it('text → pcap → text exclusive switches invalidate prior generation tokens', () => {
    noteActiveSessionKind('text')
    const t1 = getLifecycleGeneration()
    disposeActiveSession()
    noteActiveSessionKind('pcap')
    const t2 = getLifecycleGeneration()
    expect(isLifecycleGenerationCurrent(t1)).toBe(false)
    disposeActiveSession()
    noteActiveSessionKind('text')
    const t3 = getLifecycleGeneration()
    expect(isLifecycleGenerationCurrent(t2)).toBe(false)
    expect(isLifecycleGenerationCurrent(t3)).toBe(true)
  })

  it('leak/resource: after dispose no session model, staging, resolve payload or mapping snapshot', async () => {
    noteActiveSessionKind('correlation')
    buildSessionModel({
      text: 'x\n',
      detection: minimalDetection(),
      fileName: 'x.log',
      byteLength: 2,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: new Uint8Array([1]),
    })
    replaceStagingItems([readyStaging('s1', 'a.log')])
    setResolveOnlyPayload(emptyBundle(), 'p.bin')
    await getSharedMappingClient().resolve('g', 's', [
      { category: 'ip', canonical: '1.1.1.1', constraint: { kind: 'ipv4-wire' } },
    ])

    disposeActiveSession()

    expect(getSessionModel()).toBeNull()
    expect(getPcapSession()).toBeNull()
    expect(getStagingItems()).toEqual([])
    expect(getResolveOnlyPayload()).toBeNull()
    expect(getSharedMappingClient().getPublishedSnapshot()).toBeNull()
    expect(getSharedMappingClient().getPublishedRevision()).toBe(0)
  })
})
