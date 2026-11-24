import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import {
  exportActiveMappingBundle,
  importMappingBundleFile,
  releaseBundleCryptoSession,
  BundleLifecycleError,
} from '../../src/features/mapping-bundle/bundleController'
import {
  clearResolveOnlyModel,
  getResolveOnlyPayload,
  isResolveOnlyActive,
} from '../../src/features/resolve-only/resolveOnlyModel'
import { buildSessionModel, clearSessionModel } from '../../src/features/workspace/sessionModel'
import { useAppStore } from '../../src/app/store'

vi.mock('../../src/features/export-log/exportCoordinator.ts', () => ({
  downloadBlob: vi.fn(),
}))

describe('Stage 21 bundle lifecycle', () => {
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

  it('exports active mapping as readable JSON', async () => {
    const client = new MappingWorkerClient(createInProcessMappingWorkerFactory())
    setSharedMappingClientForTests(client)
    await client.resolve('g1', 'text', [{
      category: 'ip',
      canonical: '10.0.0.8',
      constraint: { kind: 'ipv4-wire' },
    }])

    buildSessionModel({
      text: 'line\n',
      detection: {
        requestId: 'r',
        packedMatches: { starts: new Uint32Array(0), lengths: new Uint32Array(0), lines: new Uint32Array(0), entityIndexes: new Uint32Array(0), flags: new Uint8Array(0) },
        entities: [],
        lineCount: 1,
        failedRuleIds: [],
      },
      fileName: 'test.log',
      byteLength: 5,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: new Uint8Array([10]),
    })

    const result = await exportActiveMappingBundle({ mode: 'text' })
    expect(result.byteLength).toBeGreaterThan(0)
    expect(result.fileName).toMatch(/\.rnd-mapping-bundle\.json$/)

    const { downloadBlob } = await import('../../src/features/export-log/exportCoordinator.ts')
    const downloadMock = downloadBlob as ReturnType<typeof vi.fn>
    const blobArg = downloadMock.mock.calls.at(-1)?.[1] as Blob
    const text = await blobArg.text()
    expect(text).toContain('"canonical": "10.0.0.8"')
    expect(text.trimStart().startsWith('{')).toBe(true)
  })

  it('import opens resolve-only model without anonymization session', async () => {
    const mapClient = new MappingWorkerClient(createInProcessMappingWorkerFactory())
    setSharedMappingClientForTests(mapClient)
    await mapClient.resolve('g1', 'text', [{
      category: 'ip',
      canonical: '10.0.0.9',
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
      fileName: 'imp.log',
      byteLength: 2,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: new Uint8Array([10]),
    })

    await exportActiveMappingBundle({ mode: 'text' })

    const { downloadBlob } = await import('../../src/features/export-log/exportCoordinator.ts')
    const downloadMock = downloadBlob as ReturnType<typeof vi.fn>
    const blobArg = downloadMock.mock.calls.at(-1)?.[1] as Blob
    const file = new File([await blobArg.arrayBuffer()], 'test.rnd-mapping-bundle.json')

    clearSessionModel()
    resetSharedMappingClient()

    const imported = await importMappingBundleFile({ file })
    expect(imported.entryCount).toBeGreaterThan(0)
    expect(isResolveOnlyActive()).toBe(true)
    expect(getResolveOnlyPayload()?.entries[0]?.canonical).toBe('10.0.0.9')
    expect(useAppStore.getState().phase).toBe('empty')
  })

  it('release clears resolve-only payload', async () => {
    const client = new MappingWorkerClient(createInProcessMappingWorkerFactory())
    setSharedMappingClientForTests(client)
    await client.resolve('g1', 'text', [{
      category: 'ip',
      canonical: '10.0.0.3',
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
      fileName: 'r.log',
      byteLength: 2,
      mode: 'common',
      workerPlanTrusted: true,
      lineEndings: new Uint8Array([10]),
    })
    await exportActiveMappingBundle({ mode: 'text' })
    const { downloadBlob } = await import('../../src/features/export-log/exportCoordinator.ts')
    const blobArg = (downloadBlob as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[1] as Blob
    const file = new File([await blobArg.arrayBuffer()], 'm.rnd-mapping-bundle.json')
    await importMappingBundleFile({ file })
    expect(isResolveOnlyActive()).toBe(true)

    releaseBundleCryptoSession()
    expect(isResolveOnlyActive()).toBe(false)
    expect(getResolveOnlyPayload()).toBeNull()
  })

  it('fails export when mapping is empty', async () => {
    await expect(exportActiveMappingBundle({ mode: 'text' })).rejects.toBeInstanceOf(
      BundleLifecycleError,
    )
  })
})

describe('Stage 21 store secret guard', () => {
  it('Zustand store never contains bundle fields', () => {
    const raw = JSON.stringify(useAppStore.getState())
    expect(raw.toLowerCase()).not.toContain('mappingbundlepayload')
  })
})
