import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { CORRELATION_PASTE_LIMITS } from '../../src/domain/capabilityContract'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import {
  clearCorrelationSession,
  createTextSourceAdapter,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  stageCorrelationDescriptors,
} from '../../src/correlation'

function pasteFile(bytes: number): File {
  return new File(['x'.repeat(bytes)], 'paste.log', { type: 'text/plain' })
}

describe('Stage 24 paste aggregate limits', () => {
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
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
  })

  it('rejects paste aggregate over explicit cap', async () => {
    const half = Math.floor(CORRELATION_PASTE_LIMITS.maxAggregateBytes / 2) + 1
    const staged = await stageCorrelationDescriptors([
      { sourceId: 'p1', kind: SK.Text, file: pasteFile(half), inputKind: 'paste' },
      { sourceId: 'p2', kind: SK.Text, file: pasteFile(half), inputKind: 'paste' },
    ])
    expect('ok' in staged).toBe(false)
    if ('ok' in staged) return
    expect(staged.code).toBe('correlation-paste-aggregate-too-large')
  })
})
