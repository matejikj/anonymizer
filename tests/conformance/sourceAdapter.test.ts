import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import { createTextSourceAdapter } from '../../src/correlation/textSourceAdapter'
import { runSourceAdapterConformance } from './sourceAdapterSuite'

describe('Stage 23 text SourceAdapter conformance', () => {
  beforeEach(() => {
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
  })

  afterEach(() => {
    resetSharedMappingClient()
  })

  it('passes shared conformance suite', async () => {
    const adapter = createTextSourceAdapter({
      createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
    })
    const file = new File(['client 10.0.0.12 connected\n'], 'conf.log', { type: 'text/plain' })
    await runSourceAdapterConformance({
      adapter,
      sampleFile: file,
      generationId: 'conf-g1',
      sourceId: 'conf-text',
    })
    expect(adapter.kind).toBe(SK.Text)
  })
})
