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
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import {
  buildCorrelationEntityRows,
  buildFlatOccurrenceList,
  getCorrelationWorkspaceSummary,
  resetCorrelationReviewModel,
  stepFlatOccurrence,
} from '../../src/correlation/correlationReviewModel'
import { useAppStore } from '../../src/app/store'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Stage 28 correlation review model', () => {
  beforeEach(async () => {
    clearCorrelationSession()
    resetSharedMappingClient()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    resetCorrelationReviewModel()
    useAppStore.getState().resetSession()

    await stageCorrelationDescriptors([
      { sourceId: 'as', kind: SK.Text, file: textFile('as.log', 'host 10.0.0.5 seen\n') },
      { sourceId: 'dot', kind: SK.Text, file: textFile('dot.log', 'client 10.0.0.5 ok\n') },
    ])
    await runCorrelationSession()
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
  })

  it('builds shared entity rows for values in multiple sources', () => {
    const shared = buildCorrelationEntityRows('shared')
    expect(shared.length).toBeGreaterThan(0)
    expect(shared.every((r) => r.shared)).toBe(true)
    expect(shared.every((r) => r.sourceIds.length >= 2)).toBe(true)
  })

  it('orders flat occurrences deterministically across sources', () => {
    const list = buildFlatOccurrenceList()
    expect(list.length).toBeGreaterThan(0)
    const first = stepFlatOccurrence(0)
    expect(first).not.toBeNull()
    const second = stepFlatOccurrence(1)
    expect(second).not.toBeNull()
    expect(second?.sourceId).toBeDefined()
  })

  it('summarizes ready sources after processing', () => {
    const summary = getCorrelationWorkspaceSummary()
    expect(summary.sourceCount).toBe(2)
    expect(summary.readyCount).toBe(2)
    expect(summary.reviewCount).toBe(0)
  })
})
