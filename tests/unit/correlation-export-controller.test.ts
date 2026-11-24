import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import {
  allocateUniqueOutputNames,
  buildCorrelationExportPreview,
  clearCorrelationSession,
  createTextSourceAdapter,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  runCorrelationExport,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import { updateSourceRecord } from '../../src/correlation/correlationSessionModel'
import { resetCorrelationExportForTests, getCorrelationCompletionState } from '../../src/correlation/export/correlationExportModel'
import * as shareManifest from '../../src/correlation/export/correlationShareManifest'
import * as sinks from '../../src/pcap/export/sinks'
import { useAppStore } from '../../src/app/store'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Step 3 correlation export controller', () => {
  const downloads: Array<{ name: string; size: number }> = []

  beforeEach(async () => {
    downloads.length = 0
    vi.spyOn(sinks, 'pickExportDirectory').mockResolvedValue(null)
    vi.spyOn(sinks, 'triggerBlobDownload').mockImplementation((blob, fileName) => {
      downloads.push({ name: fileName, size: blob.size })
    })

    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationExportForTests()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    useAppStore.getState().resetSession()

    await stageCorrelationDescriptors([
      { sourceId: 'as', kind: SK.Text, file: textFile('as-server.log', 'host 10.0.0.5 seen\n') },
      { sourceId: 'dot', kind: SK.Text, file: textFile('dot.log', 'client 10.0.0.5 ok\n') },
    ])
    await runCorrelationSession()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    clearCorrelationSession()
    resetSharedMappingClient()
  })

  it('lists all sources including failed ones in preview', () => {
    updateSourceRecord('dot', {
      phase: 'failed',
      exportState: 'blocked',
      errorMessage: 'Syntetická chyba',
      plan: null,
    })
    const preview = buildCorrelationExportPreview({ scope: 'set' })
    expect(preview.files).toHaveLength(2)
    const failed = preview.files.find((f) => f.sourceId === 'dot')
    expect(failed?.exportable).toBe(false)
    expect(failed?.skipReason).toBe('failed')
    expect(failed?.skipDetail).toContain('Syntetická')
    expect(preview.partialOnly).toBe(true)
    expect(preview.dataFileCount).toBe(1)
  })

  it('allocates unique output names without silent overwrite', () => {
    const names = allocateUniqueOutputNames([
      { sourceId: 'a', outputFileName: 'same.anonym.log' },
      { sourceId: 'b', outputFileName: 'same.anonym.log' },
      { sourceId: 'c', outputFileName: 'same.anonym.log' },
    ])
    expect(names.get('a')).toBe('same.anonym.log')
    expect(names.get('b')).toBe('same.anonym-2.log')
    expect(names.get('c')).toBe('same.anonym-3.log')
  })

  it('exports multiple text sources and separates data vs companion counts', async () => {
    const result = await runCorrelationExport({ partial: false, preferDirectoryPicker: false })
    expect(result.ok, result.ok ? '' : `${result.code}: ${result.message}`).toBe(true)
    if (!result.ok) return
    expect(result.dataFiles.length).toBeGreaterThanOrEqual(2)
    expect(result.exportedFiles.length).toBe(result.dataFiles.length + result.companionFiles.length)
    expect(downloads.length).toBeGreaterThanOrEqual(2)
    expect(result.downloadUnverified).toBe(true)
    expect(downloads.every((d) => d.size > 0)).toBe(true)
  })

  it('exports current-file scope only', async () => {
    const result = await runCorrelationExport({
      scope: 'current',
      currentSourceId: 'as',
      preferDirectoryPicker: false,
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.dataFiles).toHaveLength(1)
    expect(result.dataFiles[0]).toMatch(/as-server/)
  })

  it('cancels remaining exports and reports completed files', async () => {
    const ac = new AbortController()
    ac.abort()
    const result = await runCorrelationExport({ preferDirectoryPicker: false, signal: ac.signal })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.code).toBe('cancelled')
  })

  it('partial export skips failed sources but writes ready ones', async () => {
    updateSourceRecord('dot', {
      phase: 'failed',
      exportState: 'blocked',
      errorMessage: 'broken',
      plan: null,
    })
    const result = await runCorrelationExport({ partial: true, preferDirectoryPicker: false })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.partial).toBe(true)
    expect(result.dataFiles.length).toBe(1)
    expect(result.skippedFiles.some((f) => f.sourceId === 'dot')).toBe(true)
  })

  it('soft-fails unsafe companion manifest without sticking after data downloads', async () => {
    vi.spyOn(shareManifest, 'needsShareableCorrelationManifest').mockReturnValue(true)
    vi.spyOn(shareManifest, 'buildShareableCorrelationManifest').mockReturnValue({
      format: 'rnd-log-anonymizer-correlation-manifest',
      schemaVersion: 1,
      partial: false,
      sources: [
        { sourceId: 'as', outputFileName: 'as-server.anonym.log', kind: 'text' },
        { sourceId: 'dot', outputFileName: 'dot.anonym.log', kind: 'text' },
      ],
      correlationGroups: [{ tag: 'c1-test', category: 'ip', aliases: ['192.0.2.1', '192.0.2.2'] }],
    })
    vi.spyOn(shareManifest, 'assertShareableManifestHasNoLeaks').mockImplementation(() => {
      throw new Error('Shareable manifest must not contain original identifier sample')
    })

    const result = await runCorrelationExport({ partial: false, preferDirectoryPicker: false })
    expect(result.ok, result.ok ? '' : `${result.code}: ${result.message}`).toBe(true)
    if (!result.ok) return
    expect(result.dataFiles.length).toBeGreaterThanOrEqual(2)
    expect(result.manifestExported).toBe(false)
    expect(result.companionFiles).toEqual([])
    expect(downloads.some((d) => d.name === shareManifest.SHAREABLE_MANIFEST_FILE_NAME)).toBe(false)
    const completion = getCorrelationCompletionState()
    expect(completion?.shareableWithAi).toBe(false)
  })
})
