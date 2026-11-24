import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import {
  exportActiveMappingBundle,
  releaseBundleCryptoSession,
} from '../../src/features/mapping-bundle/bundleController'
import { buildSessionModel, clearSessionModel, getSessionModel } from '../../src/features/workspace/sessionModel'
import { useAppStore } from '../../src/app/store'
import {
  closeResolveReturnAndClear,
  getResolveReturnError,
  getResolveReturnStep,
  openResolveReturnFromEmpty,
  resetResolveReturnForTests,
  resolveReturnGenericError,
  selectResolveReturnBundle,
} from '../../src/features/resolve-only/resolveReturnController'
import {
  getResolveOnlyPayload,
  isResolveOnlyActive,
} from '../../src/features/resolve-only/resolveOnlyModel'
import { BundleLifecycleError } from '../../src/features/mapping-bundle/bundleController'
import { BUNDLE_CODEC_ERROR } from '../../src/mapping/bundle/errors'
import { MAPPING_CAPABILITY_LIMITS } from '../../src/domain/capabilityContract'
import { exactLookupByAlias, scanAiReport } from '../../src/mapping/resolve'
import { cs } from '../../src/i18n/cs'

vi.mock('../../src/features/export-log/exportCoordinator.ts', () => ({
  downloadBlob: vi.fn(),
}))

async function makeBundleFile(): Promise<File> {
  const mapClient = new MappingWorkerClient(createInProcessMappingWorkerFactory())
  setSharedMappingClientForTests(mapClient)
  await mapClient.resolve('g30', 'text', [
    {
      category: 'ip',
      canonical: '10.0.0.42',
      constraint: { kind: 'ipv4-wire' },
    },
  ])

  buildSessionModel({
    text: 'host 10.0.0.42\n',
    detection: {
      requestId: 'r',
      packedMatches: {
        starts: new Uint32Array(0),
        lengths: new Uint32Array(0),
        lines: new Uint32Array(0),
        entityIndexes: new Uint32Array(0),
        flags: new Uint8Array(0),
      },
      entities: [],
      lineCount: 1,
      failedRuleIds: [],
    },
    fileName: 's30.log',
    byteLength: 16,
    mode: 'common',
    workerPlanTrusted: true,
    lineEndings: new Uint8Array([10]),
  })

  await exportActiveMappingBundle({ mode: 'text' })
  const { downloadBlob } = await import('../../src/features/export-log/exportCoordinator.ts')
  const blobArg = (downloadBlob as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[1] as Blob
  clearSessionModel()
  resetSharedMappingClient()
  return new File([await blobArg.arrayBuffer()], 'map.rnd-mapping-bundle.json', {
    type: 'application/json',
  })
}

describe('Stage 30 resolve-only return flow', () => {
  beforeEach(() => {
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    clearSessionModel()
    resetResolveReturnForTests()
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    releaseBundleCryptoSession()
    resetResolveReturnForTests()
    resetSharedMappingClient()
  })

  it('two-step flow unlocks bundle without creating anonymization session', async () => {
    const file = await makeBundleFile()
    openResolveReturnFromEmpty()
    expect(useAppStore.getState().phase).toBe('resolve-only')
    expect(getResolveReturnStep()).toBe('pick-bundle')
    expect(getSessionModel()).toBeNull()

    await selectResolveReturnBundle(file)
    expect(getResolveReturnStep()).toBe('lookup')
    expect(isResolveOnlyActive()).toBe(true)
    expect(getSessionModel()).toBeNull()

    const payload = getResolveOnlyPayload()
    expect(payload?.entries.length).toBeGreaterThan(0)
    const alias = payload!.entries[0]!.alias
    const lookup = exactLookupByAlias(alias, 'imported-bundle', payload)
    expect('code' in lookup).toBe(false)
    if ('code' in lookup) return
    expect(lookup.candidates[0]?.canonical).toBe('10.0.0.42')
  })

  it('exact alias and AI report scan work after unlock', async () => {
    const file = await makeBundleFile()
    openResolveReturnFromEmpty()
    await selectResolveReturnBundle(file)
    const payload = getResolveOnlyPayload()!
    const alias = payload.entries[0]!.alias

    const exact = exactLookupByAlias(alias, 'imported-bundle', payload)
    expect('code' in exact).toBe(false)

    const scan = scanAiReport(`AI says ${alias} is the peer.`, 'imported-bundle', payload)
    expect('code' in scan).toBe(false)
    if ('code' in scan) return
    expect(scan.findings.length).toBeGreaterThan(0)
    expect(scan.findings[0]!.candidates[0]?.canonical).toBe('10.0.0.42')
  })

  it('invalid bundle yields a generic error without leaking details', async () => {
    openResolveReturnFromEmpty()
    const bad = new File([new TextEncoder().encode('not a bundle')], 'bad.rnd-mapping-bundle.json')
    await selectResolveReturnBundle(bad)
    expect(getResolveReturnStep()).toBe('pick-bundle')
    expect(getResolveReturnError()).toBe(cs.resolveReturn.errorGeneric)
    expect(isResolveOnlyActive()).toBe(false)
  })

  it('oversize and payload failures share bounded generic messages', () => {
    expect(resolveReturnGenericError(new BundleLifecycleError(BUNDLE_CODEC_ERROR.payloadInvalid, 'bad payload'))).toBe(
      cs.resolveReturn.errorGeneric,
    )
    expect(resolveReturnGenericError(new BundleLifecycleError(BUNDLE_CODEC_ERROR.oversize, 'big'))).toBe(
      cs.resolveReturn.errorOversize,
    )
  })

  it('rejects oversize file at pick step', async () => {
    openResolveReturnFromEmpty()
    const huge = new File([new Uint8Array(MAPPING_CAPABILITY_LIMITS.maxBundleImportBytes + 1)], 'huge.bundle')
    await selectResolveReturnBundle(huge)
    expect(getResolveReturnStep()).toBe('pick-bundle')
    expect(getResolveReturnError()).toBe(cs.resolveReturn.errorOversize)
  })

  it('close clears imported model and returns to empty', async () => {
    const file = await makeBundleFile()
    openResolveReturnFromEmpty()
    await selectResolveReturnBundle(file)
    expect(isResolveOnlyActive()).toBe(true)

    closeResolveReturnAndClear()
    expect(isResolveOnlyActive()).toBe(false)
    expect(getResolveOnlyPayload()).toBeNull()
    expect(useAppStore.getState().phase).toBe('empty')
    expect(getResolveReturnStep()).toBe('pick-bundle')
  })
})
