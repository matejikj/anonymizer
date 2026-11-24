import { describe, expect, it, beforeEach } from 'vitest'
import {
  getCorrelationProgressState,
  initCorrelationProgress,
  markCorrelationSourceActive,
  markCorrelationSourceDone,
  reportCorrelationSourceProgress,
  resetCorrelationProgress,
} from '../../src/correlation/correlationProgressModel'
import {
  clearCorrelationSessionModel,
  createCorrelationSessionModel,
} from '../../src/correlation/correlationSessionModel'
import { buildStagedSourceRecord } from '../../src/correlation/correlationSession'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Stage 28 correlation progress model', () => {
  beforeEach(() => {
    resetCorrelationProgress()
    clearCorrelationSessionModel()
    createCorrelationSessionModel({
      sessionId: 's1',
      generationId: 'g1',
      descriptors: [
        { sourceId: 'a', kind: SK.Text, file: textFile('a.log', 'x\n') },
        { sourceId: 'b', kind: SK.Text, file: textFile('b.log', 'y\n') },
      ],
      buildRecord: buildStagedSourceRecord,
    })
  })

  it('initializes waiting rows for all staged sources', () => {
    initCorrelationProgress('Start')
    const state = getCorrelationProgressState()
    expect(state.sources).toHaveLength(2)
    expect(state.sources.every((s) => s.status === 'waiting')).toBe(true)
    expect(state.aggregatePercent).toBe(0)
  })

  it('updates aggregate percent when a source becomes active', () => {
    initCorrelationProgress('Start')
    markCorrelationSourceActive('a')
    const state = getCorrelationProgressState()
    expect(state.sources[0]?.status).toBe('active')
    expect(state.aggregatePercent).toBeGreaterThan(0)
  })

  it('tracks startedAt and reports progress during line analysis', () => {
    initCorrelationProgress('Start')
    expect(getCorrelationProgressState().startedAt).toBeGreaterThan(0)
    markCorrelationSourceActive('a')
    reportCorrelationSourceProgress('a', 'lines', 50, 100)
    const state = getCorrelationProgressState()
    expect(state.aggregatePercent).toBeGreaterThan(0)
  })

  it('marks source done and increases aggregate', () => {
    initCorrelationProgress('Start')
    markCorrelationSourceActive('a')
    markCorrelationSourceDone('a', 12)
    expect(getCorrelationProgressState().sources[0]?.status).toBe('done')
    expect(getCorrelationProgressState().aggregatePercent).toBe(50)
  })
})
