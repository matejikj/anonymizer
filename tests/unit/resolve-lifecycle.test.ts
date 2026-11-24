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
import { buildSessionModel, clearSessionModel } from '../../src/features/workspace/sessionModel'
import { useAppStore } from '../../src/app/store'

vi.mock('../../src/features/export-log/exportCoordinator.ts', () => ({
  downloadBlob: vi.fn(),
}))

describe('Stage 22 resolve lifecycle', () => {
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

  it('closing resolve workspace clears decrypted mapping from module model', async () => {
    const mapClient = new MappingWorkerClient(createInProcessMappingWorkerFactory())
    setSharedMappingClientForTests(mapClient)
    await mapClient.resolve('g1', 'text', [{
      category: 'ip',
      canonical: '10.0.0.77',
      constraint: { kind: 'ipv4-wire' },
    }])

    buildSessionModel({
      text: 'z\n',
      detection: {
        requestId: 'r',
        packedMatches: { starts: new Uint32Array(0), lengths: new Uint32Array(0), lines: new Uint32Array(0), entityIndexes: new Uint32Array(0), flags: new Uint8Array(0) },
        entities: [],
        lineCount: 1,
        failedRuleIds: [],
      },
      fileName: 'close.log',
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
    expect(getResolveOnlyPayload()?.entries.length).toBeGreaterThan(0)

    releaseBundleCryptoSession()
    useAppStore.getState().exitResolveOnly()

    expect(isResolveOnlyActive()).toBe(false)
    expect(getResolveOnlyPayload()).toBeNull()
    expect(useAppStore.getState().phase).toBe('empty')
  })
})
