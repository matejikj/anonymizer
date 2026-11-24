import { describe, expect, it } from 'vitest'
import { buildSessionModel, clearSessionModel, getSessionModel } from '../../src/features/workspace/sessionModel.ts'
import { analyze } from '../../src/engine/analyze.ts'
import { toTransferableBuffers, packResolvedMatches, entityKeyToIndex } from '../../src/engine/packedMatchIndex.ts'
import { SAMPLE_LOG } from '../../src/features/import-log/sampleLog.ts'

describe('sessionModel', () => {
  it('builds shared plan and clears previous session', () => {
    clearSessionModel()
    const text = SAMPLE_LOG
    const result = analyze(text)
    const packed = packResolvedMatches(
      result.matches,
      entityKeyToIndex(result.entities),
      (k) => result.entitiesByKey.get(k)?.enabled ?? true,
    )
    const { buffers } = toTransferableBuffers(packed)
    const model = buildSessionModel({
      text,
      detection: {
        requestId: 't1',
        packedMatches: buffers,
        entities: result.entitySummaries,
        lineCount: result.lineCount,
        failedRuleIds: [],
      },
      fileName: 'sample.log',
      byteLength: text.length,
      mode: 'common',
    })
    expect(getSessionModel()).toBe(model)
    expect(model.plan.replacements.length).toBe(model.packed.starts.length)
    expect(model.meta.entityCount).toBeGreaterThan(0)
    expect(model.original.includes('10.16.1.105')).toBe(true)

    buildSessionModel({
      text: 'only 10.0.0.1\n',
      detection: {
        requestId: 't2',
        packedMatches: buffers,
        entities: result.entitySummaries,
        lineCount: 1,
        failedRuleIds: [],
      },
      fileName: null,
      byteLength: 20,
      mode: 'common',
    })
    expect(getSessionModel()?.meta.generation).toBe('t2')
    clearSessionModel()
    expect(getSessionModel()).toBeNull()
  })
})
