import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import {
  exportActiveMappingBundle,
  importMappingBundleFile,
  releaseBundleCryptoSession,
} from '../../src/features/mapping-bundle/bundleController'
import {
  clearResolveOnlyModel,
  getResolveOnlyPayload,
  isResolveOnlyActive,
} from '../../src/features/resolve-only/resolveOnlyModel'
import { buildSessionModel, clearSessionModel, getSessionModel } from '../../src/features/workspace/sessionModel'
import { exactLookupByAlias } from '../../src/mapping/resolve'
import { useAppStore } from '../../src/app/store'

vi.mock('../../src/features/export-log/exportCoordinator.ts', () => ({
  downloadBlob: vi.fn(),
}))

describe('Stage 22 resolve workspace sources', () => {
  beforeEach(() => {
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    clearSessionModel()
    clearResolveOnlyModel()
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    releaseBundleCryptoSession()
    resetSharedMappingClient()
  })

  it('exact lookup works over active session mapping', async () => {
    const client = new MappingWorkerClient(createInProcessMappingWorkerFactory())
    setSharedMappingClientForTests(client)
    await client.resolve('g1', 'text', [{
      category: 'ip',
      canonical: '192.168.1.50',
      constraint: { kind: 'ipv4-wire' },
    }])

    buildSessionModel({
      text: '192.168.1.50\n',
      detection: {
        requestId: 'r',
        packedMatches: { starts: new Uint32Array(0), lengths: new Uint32Array(0), lines: new Uint32Array(0), entityIndexes: new Uint32Array(0), flags: new Uint8Array(0) },
        entities: [],
        lineCount: 1,
        failedRuleIds: [],
      },
      fileName: 'active.log',
      byteLength: 14,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: new Uint8Array([10]),
    })

    const snapshot = client.getPublishedSnapshot()
    const alias = snapshot?.entries[0]?.alias
    expect(alias).toBeTruthy()

    const result = exactLookupByAlias(alias!, 'active-session')
    expect('code' in result).toBe(false)
    if ('code' in result) return
    expect(result.candidates[0]?.canonical).toBe('192.168.1.50')
  })

  it('exact lookup works over imported bundle payload', async () => {
    const mapClient = new MappingWorkerClient(createInProcessMappingWorkerFactory())
    setSharedMappingClientForTests(mapClient)
    await mapClient.resolve('g1', 'text', [{
      category: 'ip',
      canonical: '10.1.2.3',
      constraint: { kind: 'ipv4-wire' },
    }])

    buildSessionModel({
      text: 'x\n',
      detection: {
        requestId: 'r',
        packedMatches: { starts: new Uint32Array(0), lengths: new Uint32Array(0), lines: new Uint32Array(0), entityIndexes: new Uint32Array(0), flags: new Uint8Array(0) },
        entities: [],
        lineCount: 1,
        failedRuleIds: [],
      },
      fileName: 'exp.log',
      byteLength: 2,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: new Uint8Array([10]),
    })

    await exportActiveMappingBundle({ mode: 'text' })
    const { downloadBlob } = await import('../../src/features/export-log/exportCoordinator.ts')
    const blobArg = (downloadBlob as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[1] as Blob
    const file = new File([await blobArg.arrayBuffer()], 'bundle.rnd-log-anonymizer-mapping', { type: 'application/octet-stream' })

    clearSessionModel()
    resetSharedMappingClient()

    await importMappingBundleFile({ file })
    const payload = getResolveOnlyPayload()
    expect(payload).not.toBeNull()
    expect(getSessionModel()).toBeNull()

    const alias = payload!.entries[0]!.alias
    const result = exactLookupByAlias(alias, 'imported-bundle', payload)
    expect('code' in result).toBe(false)
    if ('code' in result) return
    expect(result.candidates[0]?.canonical).toBe('10.1.2.3')
  })

  it('resolve-only import never creates anonymization session', async () => {
    const mapClient = new MappingWorkerClient(createInProcessMappingWorkerFactory())
    setSharedMappingClientForTests(mapClient)
    await mapClient.resolve('g1', 'text', [{
      category: 'ip',
      canonical: '10.9.9.9',
      constraint: { kind: 'ipv4-wire' },
    }])

    buildSessionModel({
      text: 'y\n',
      detection: {
        requestId: 'r',
        packedMatches: { starts: new Uint32Array(0), lengths: new Uint32Array(0), lines: new Uint32Array(0), entityIndexes: new Uint32Array(0), flags: new Uint8Array(0) },
        entities: [],
        lineCount: 1,
        failedRuleIds: [],
      },
      fileName: 'only.log',
      byteLength: 2,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: new Uint8Array([10]),
    })

    await exportActiveMappingBundle({ mode: 'text' })
    const { downloadBlob } = await import('../../src/features/export-log/exportCoordinator.ts')
    const blobArg = (downloadBlob as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[1] as Blob
    const file = new File([await blobArg.arrayBuffer()], 'bundle.rnd-log-anonymizer-mapping', { type: 'application/octet-stream' })

    clearSessionModel()
    resetSharedMappingClient()

    await importMappingBundleFile({ file })
    expect(isResolveOnlyActive()).toBe(true)
    expect(getSessionModel()).toBeNull()
    expect(useAppStore.getState().sessionEpoch).toBe(0)
  })
})
