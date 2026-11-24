import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import {
  clearCorrelationSession,
  createTextSourceAdapter,
  getCorrelationSource,
  getCorrelationSessionModel,
  isSingleSourceSession,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import { testSourceAdapter } from '../helpers/testSourceAdapter.ts'
import { useAppStore } from '../../src/app/store'
import { runSourceAdapterConformance } from '../conformance/sourceAdapterSuite'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Stage 23 correlation session port', () => {
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
    registerSourceAdapter(testSourceAdapter)
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
  })

  it('stages and processes a single source as valid special case', async () => {
    const staged = await stageCorrelationDescriptors([
      { sourceId: 'log-a', kind: SK.Text, file: textFile('a.log', 'contact 10.0.0.5 today\n') },
    ])
    expect('ok' in staged && staged.ok).toBe(true)
    expect(isSingleSourceSession()).toBe(true)

    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)
    if (!('ok' in processed) || !processed.ok) return

    const record = getCorrelationSource('log-a')
    expect(record?.phase).toBe('planned')
    expect(record?.plan?.kind).toBe('text')
    expect(processed.mappingRevision).toBeGreaterThan(0)
  })

  it('stages eight descriptors through the same session port', async () => {
    const descriptors = Array.from({ length: 8 }, (_, i) => ({
      sourceId: `src-${i}`,
      kind: SK.Text as const,
      file: textFile(`f${i}.log`, `line ${i} 10.0.0.${i + 1}\n`),
    }))
    const staged = await stageCorrelationDescriptors(descriptors)
    expect('ok' in staged && staged.ok).toBe(true)
    if (!('ok' in staged) || !staged.ok) return
    expect(staged.sourceCount).toBe(8)

    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)
    if (!('ok' in processed) || !processed.ok) return
    expect(processed.sourceCount).toBe(8)
    expect(getCorrelationSessionModel()?.phase).toBe('ready')
  })

  it('third adapter registers without orchestration changes', async () => {
    const file = new File(['10.0.0.1'], 'probe.testsrc', { type: 'application/octet-stream' })
    await runSourceAdapterConformance({
      adapter: testSourceAdapter,
      sampleFile: file,
      generationId: 'g-test',
      sourceId: 'test-1',
    })

    const staged = await stageCorrelationDescriptors([
      { sourceId: 't1', kind: SK.Text, file: textFile('x.log', '10.0.0.2\n') },
    ])
    expect('ok' in staged && staged.ok).toBe(true)
  })
})

describe('Stage 23 store guard', () => {
  it('Zustand store holds only small correlation view fields', () => {
    const raw = JSON.stringify(useAppStore.getState())
    expect(raw.toLowerCase()).not.toContain('packedmatchindex')
    expect(raw.toLowerCase()).not.toContain('mappingregistry')
    expect(raw.toLowerCase()).not.toContain('correlationsourceplan')
    expect(useAppStore.getState().correlationSourceCount).toBe(0)
  })
})
