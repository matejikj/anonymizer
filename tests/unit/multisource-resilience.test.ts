import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import {
  cancelInitialCorrelationProcessing,
  clearCorrelationSession,
  createTextSourceAdapter,
  enterCorrelationProcessingPhase,
  getCorrelationUiPhase,
  getStagingItems,
  openCorrelationStaging,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  resetCorrelationUiPhase,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import {
  buildStagingItemsFromFiles,
  replaceStagingItems,
  resetStagingForTests,
} from '../../src/correlation/import'
import { useAppStore } from '../../src/app/store'
import { preflightStagingFile } from '../../src/correlation/import/sourcePreflightPort'
import { MAX_TEXT_FILE_BYTES } from '../../src/domain/capabilityContract'
import { rovingKeyNavigate } from '../../src/features/correlation-workspace/rovingKeyNavigate'
import {
  announceCorrelationSource,
  getCorrelationSourceLiveText,
  resetCorrelationLiveAnnouncerForTests,
} from '../../src/correlation/correlationLiveAnnouncer'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Stage 31 resilience and a11y foundations', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationUiPhase()
    resetStagingForTests()
    resetCorrelationLiveAnnouncerForTests()
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
    resetCorrelationUiPhase()
  })

  it('uses exclusive CorrelationUiPhase discriminated union for staging/processing', () => {
    openCorrelationStaging()
    expect(getCorrelationUiPhase()).toEqual({ kind: 'staging' })
    expect(useAppStore.getState().phase).toBe('correlation-staging')

    enterCorrelationProcessingPhase()
    expect(getCorrelationUiPhase().kind).toBe('processing')
    expect(useAppStore.getState().phase).toBe('correlation-processing')
  })

  it('cancel initial analysis returns to staging with list preserved', async () => {
    const files = [textFile('a.log', 'host 10.0.0.1\n'), textFile('b.log', 'host 10.0.0.1\n')]
    replaceStagingItems(await buildStagingItemsFromFiles(files))
    openCorrelationStaging()
    expect(getStagingItems().length).toBe(2)

    await stageCorrelationDescriptors(
      getStagingItems()
        .filter((i) => i.status === 'ready' || i.status === 'duplicate-warning')
        .map((i) => ({
          sourceId: i.id,
          kind: i.kind,
          file: i.file,
        })),
    )
    enterCorrelationProcessingPhase()
    await cancelInitialCorrelationProcessing()

    expect(getCorrelationUiPhase().kind).toBe('staging')
    expect(useAppStore.getState().phase).toBe('correlation-staging')
    expect(getStagingItems().length).toBe(2)
  })

  it('per-file oversize message includes size and limit without double MiB', async () => {
    const huge = new File([new Uint8Array(MAX_TEXT_FILE_BYTES + 1)], 'big.log', { type: 'text/plain' })
    // File constructor may not allocate full bytes in all environments — force size via spy if needed
    Object.defineProperty(huge, 'size', { value: MAX_TEXT_FILE_BYTES + 1024 })
    const result = await preflightStagingFile(huge, SK.Text)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.message).toMatch(/limit pro tento typ/)
    expect(result.message).toMatch(/Ostatní soubory můžete ponechat/)
    expect(result.message).not.toMatch(/MiB MiB/)
  })

  it('roving keyboard navigates with arrows Home End Enter', () => {
    const activated: number[] = []
    const selected: number[] = []
    const prevent = () => undefined
    rovingKeyNavigate({ key: 'ArrowDown', preventDefault: prevent }, {
      itemCount: 3,
      activeIndex: 0,
      onActivate: (i) => activated.push(i),
      onSelect: (i) => selected.push(i),
    })
    expect(activated.at(-1)).toBe(1)
    rovingKeyNavigate({ key: 'End', preventDefault: prevent }, {
      itemCount: 3,
      activeIndex: 1,
      onActivate: (i) => activated.push(i),
      onSelect: (i) => selected.push(i),
    })
    expect(activated.at(-1)).toBe(2)
    rovingKeyNavigate({ key: 'Home', preventDefault: prevent }, {
      itemCount: 3,
      activeIndex: 2,
      onActivate: (i) => activated.push(i),
      onSelect: (i) => selected.push(i),
    })
    expect(activated.at(-1)).toBe(0)
    rovingKeyNavigate({ key: 'Enter', preventDefault: prevent }, {
      itemCount: 3,
      activeIndex: 0,
      onActivate: (i) => activated.push(i),
      onSelect: (i) => selected.push(i),
    })
    expect(selected).toEqual([0])
  })

  it('throttled live announcer updates message text', () => {
    announceCorrelationSource('Zdroj a.log, typ LOG')
    expect(getCorrelationSourceLiveText()).toBe('Zdroj a.log, typ LOG')
  })

  it('DOT+AS style pair keeps one shared IP alias across sources', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'dot', kind: SK.Text, file: textFile('dot.log', 'peer 10.0.0.5 ok\n') },
      { sourceId: 'as', kind: SK.Text, file: textFile('as.log', 'server 10.0.0.5 up\n') },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)

    const { getSharedMappingClient } = await import('../../src/mapping/sharedMappingClient')
    const snap = getSharedMappingClient().getPublishedSnapshot()
    expect(snap).toBeTruthy()
    const ipEntries = snap!.entries.filter((e) => e.category === 'ip' && e.canonical === '10.0.0.5')
    expect(ipEntries.length).toBeGreaterThanOrEqual(1)
    const alias = ipEntries[0]!.alias
    expect(alias).toBeTruthy()
    expect(ipEntries.every((e) => e.alias === alias || e.aliases.some((a) => a.alias === alias))).toBe(true)
  })
})
