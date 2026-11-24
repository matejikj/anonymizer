/**
 * T10 — text anonymization outcome view model.
 */
import { describe, expect, it } from 'vitest'
import { buildTextAnonymizationOutcome } from '../../src/features/review/textAnonymizationOutcome'
import { createDefaultCategoryMasters } from '../../src/features/review/entityState'
import { EMPTY_INCIDENT_LOG_SNAPSHOT } from '../../src/domain/anonymizationIncident'
import type { Entity } from '../../src/domain/types'

function entity(partial: Partial<Entity> & Pick<Entity, 'key' | 'category'>): Entity {
  return {
    originalSample: 'x',
    normalized: 'x',
    replacement: 'y',
    enabled: true,
    occurrenceCount: 1,
    occurrenceIndexes: new Uint32Array([0]),
    source: 'builtin',
    sourceId: 't',
    createdOrder: 0,
    ...partial,
  }
}

describe('buildTextAnonymizationOutcome', () => {
  it('AI_READY when all replaced', () => {
    const masters = createDefaultCategoryMasters()
    const outcome = buildTextAnonymizationOutcome({
      entities: [entity({ key: 'e1', category: 'ip' })],
      categoryMasters: masters,
      failedRuleIds: [],
      incidents: EMPTY_INCIDENT_LOG_SNAPSHOT,
    })
    expect(outcome.gate).toBe('AI_READY')
    expect(outcome.categories[0]?.category).toBe('ip')
  })

  it('AI_READY_WITH_GAPS when failed rules (T71 — never NOT_AI_READY)', () => {
    const masters = createDefaultCategoryMasters()
    const outcome = buildTextAnonymizationOutcome({
      entities: [entity({ key: 'e1', category: 'ip', enabled: false })],
      categoryMasters: masters,
      failedRuleIds: ['custom-1'],
      incidents: EMPTY_INCIDENT_LOG_SNAPSHOT,
    })
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.failedRuleIds).toContain('custom-1')
    expect(outcome.summarySentence.toLowerCase()).not.toMatch(/ověř|zkontrol|není připraven/)
  })

  it('disabled category still exportable; individual prefs preserved (T71/D4)', () => {
    const masters = createDefaultCategoryMasters()
    masters.ip = false
    const entities = [entity({ key: 'e1', category: 'ip' })]
    const input = { entities, categoryMasters: masters, failedRuleIds: [] }
    const disabled = buildTextAnonymizationOutcome(input)
    expect(disabled.categories[0]?.enabledUnique).toBe(0)
    expect(disabled.gate).not.toBe('NOT_AI_READY')
    expect(['AI_READY', 'AI_READY_WITH_GAPS']).toContain(disabled.gate)
    expect(entities[0].enabled).toBe(true)
    masters.ip = true
    expect(buildTextAnonymizationOutcome(input).categories[0]?.enabledUnique).toBe(1)
  })

  it('AI_READY_WITH_GAPS when incidents only', () => {
    const masters = createDefaultCategoryMasters()
    const outcome = buildTextAnonymizationOutcome({
      entities: [entity({ key: 'e1', category: 'hostname' })],
      categoryMasters: masters,
      failedRuleIds: [],
      incidents: {
        ...EMPTY_INCIDENT_LOG_SNAPSHOT,
        totalFailures: 2,
        incidents: [
          {
            unit: 'line',
            sourceId: 't',
            lineNumber: 12,
            stage: 'detection',
            reason: 'detector-exception',
            fallback: 'line-masked',
          },
        ],
        aggregates: [
          { protocol: '*', reason: 'detector-exception', fallback: 'line-masked', count: 2 },
        ],
      },
      oversizedLines: [100, 200],
    })
    expect(outcome.gate).toBe('AI_READY_WITH_GAPS')
    expect(outcome.incidentTotal).toBe(2)
    expect(outcome.oversizedLines).toEqual([100, 200])
  })
})
