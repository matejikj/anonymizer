import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import {
  countMaterializedTextSources,
  getMaterializedTextSourceId,
  materializeTextForSource,
  releaseTextMaterialization,
  selectTextSourceForPreview,
} from '../../src/correlation/textMaterialization'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'

function textFile(body: string): File {
  return new File([body], 'mem.log', { type: 'text/plain' })
}

describe('Stage 24 text materialization cache', () => {
  beforeEach(() => {
    releaseTextMaterialization()
  })

  afterEach(() => {
    releaseTextMaterialization()
  })

  it('materializes at most one text source at a time', async () => {
    const createDetectionClient = () => new DetectionWorkerClient({}, () => new FakeDetectionWorker())

    await materializeTextForSource('s1', textFile('alpha 10.0.0.1\n'), { createDetectionClient })
    expect(countMaterializedTextSources()).toBe(1)
    expect(getMaterializedTextSourceId()).toBe('s1')

    await materializeTextForSource('s2', textFile('beta 10.0.0.2\n'), { createDetectionClient })
    expect(countMaterializedTextSources()).toBe(1)
    expect(getMaterializedTextSourceId()).toBe('s2')

    selectTextSourceForPreview('s3')
    expect(countMaterializedTextSources()).toBe(0)

    releaseTextMaterialization()
    expect(countMaterializedTextSources()).toBe(0)
  })
})
