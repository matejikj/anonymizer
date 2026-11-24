import { describe, expect, it } from 'vitest'
import type { Entity } from '../../src/domain/types.ts'
import {
  applyEffectiveMatchFlags,
  buildEffectiveEntityBitset,
  createDefaultCategoryMasters,
  isEffectivelyEnabled,
  summarizeCategories,
  computeAliasSuppressedSummary,
  computeExposedSummary,
  computeSecurityLevel,
} from '../../src/features/review/entityState.ts'
import { FLAG_ENABLED } from '../../src/engine/packedMatchIndex.ts'
import { analyze } from '../../src/engine/analyze.ts'
import {
  packResolvedMatches,
  entityKeyToIndex,
} from '../../src/engine/packedMatchIndex.ts'
import { buildReplacementPlan, transformWithPlan } from '../../src/engine/transform.ts'

function entity(partial: Partial<Entity> & Pick<Entity, 'key' | 'category'>): Entity {
  return {
    originalSample: partial.originalSample ?? partial.key,
    normalized: partial.normalized ?? partial.key,
    replacement: partial.replacement ?? 'X',
    occurrenceCount: partial.occurrenceCount ?? 1,
    occurrenceIndexes: new Uint32Array(0),
    enabled: partial.enabled ?? true,
    source: 'builtin',
    sourceId: 't',
    createdOrder: 0,
    ...partial,
  }
}

describe('entity effective state', () => {
  it('preserves individual prefs when category master is toggled', () => {
    const m = createDefaultCategoryMasters()
    const e = entity({ key: 'ip::1', category: 'ip', enabled: false })
    expect(isEffectivelyEnabled(e, m)).toBe(false)
    m.ip = false
    expect(isEffectivelyEnabled(e, m)).toBe(false)
    m.ip = true
    expect(e.enabled).toBe(false)
    expect(isEffectivelyEnabled(e, m)).toBe(false)
    e.enabled = true
    expect(isEffectivelyEnabled(e, m)).toBe(true)
  })

  it('summarizes categories; T71 exposed gate is always empty when analysis done', () => {
    const m = createDefaultCategoryMasters()
    const entities = [
      entity({ key: 'ip::a', category: 'ip', occurrenceCount: 2 }),
      entity({ key: 'ip::b', category: 'ip', enabled: false, occurrenceCount: 3 }),
      entity({ key: 'email::c', category: 'email', occurrenceCount: 1 }),
    ]
    const rows = summarizeCategories(entities, m)
    const ip = rows.find((r) => r.category === 'ip')!
    expect(ip.uniqueCount).toBe(2)
    expect(ip.occurrenceCount).toBe(5)
    expect(ip.partiallyDisabled).toBe(true)

    // Gate/export: no “exposed originals” after D4 free-token.
    const exp = computeExposedSummary(entities, m)
    expect(exp.entityCount).toBe(0)
    expect(exp.occurrenceCount).toBe(0)
    const suppressed = computeAliasSuppressedSummary(entities, m)
    expect(suppressed.entityCount).toBe(1)
    expect(suppressed.occurrenceCount).toBe(3)
    expect(
      computeSecurityLevel({ analysisDone: true, failedRuleIds: [], exposed: exp }),
    ).toBe('ok')
    expect(
      computeSecurityLevel({
        analysisDone: true,
        failedRuleIds: ['custom-1'],
        exposed: exp,
      }),
    ).toBe('ok')
    expect(
      computeSecurityLevel({
        analysisDone: false,
        failedRuleIds: [],
        exposed: computeExposedSummary([], m),
      }),
    ).toBe('blocked')
  })

  it('rebuilds plan so disabled entity gets free-token, never the original (T71/D4)', () => {
    const text = 'user=disp4 ip=10.16.1.105\n'
    const result = analyze(text)
    const packed = packResolvedMatches(
      result.matches,
      entityKeyToIndex(result.entities),
      () => true,
    )
    const planOn = buildReplacementPlan(packed, result.entities)
    const outOn = transformWithPlan(text, packed, planOn)
    expect(outOn).not.toContain('disp4')
    expect(outOn).not.toContain('10.16.1.105')

    result.entities[0]!.enabled = false
    applyEffectiveMatchFlags(packed, result.entities, createDefaultCategoryMasters())
    const planOff = buildReplacementPlan(packed, result.entities)
    const outOff = transformWithPlan(text, packed, planOff)
    const disabledSample = result.entities[0]!.originalSample
    expect(outOff).not.toContain(disabledSample)
    expect(planOff.aliasSuppressedCount).toBeGreaterThan(0)

    const bits = buildEffectiveEntityBitset(
      result.entities,
      createDefaultCategoryMasters(),
    )
    expect(bits[0]).toBe(0)
    expect([...bits].some((b) => b === 1)).toBe(true)

    const matchIdx = [...packed.entityIndexes].findIndex((ei) => ei === 0)
    if (matchIdx >= 0) {
      expect(packed.flags[matchIdx]! & FLAG_ENABLED).toBe(0)
    }
  })
})
