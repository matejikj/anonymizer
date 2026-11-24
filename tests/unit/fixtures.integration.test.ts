import { describe, expect, it } from 'vitest'
import { analyze } from '../../src/engine/analyze.ts'
import { transformWithPlan } from '../../src/engine/transform.ts'
import { countPhysicalLines } from '../../src/domain/invariants.ts'
import { FIXTURE_LOGS, FIXTURE_LOGS_AVAILABLE, readFixtureLog } from '../fixtures/loadFixtures.ts'
import { allMustNotLeakTokens, MUST_NOT_LEAK } from '../fixtures/mustNotLeak.ts'

describe.skipIf(!FIXTURE_LOGS_AVAILABLE)('fixture integration (Krok 2)', () => {
  for (const name of FIXTURE_LOGS) {
    it(`anonymizes ${name} without leaking curated tokens`, () => {
      const original = readFixtureLog(name)
      const result = analyze(original)

      expect(result.lineCount).toBe(countPhysicalLines(original))
      expect(countPhysicalLines(result.anonymized)).toBe(countPhysicalLines(original))
      expect(transformWithPlan(original, result.packed, result.plan)).toBe(result.anonymized)

      const presentInOriginal = allMustNotLeakTokens().filter((t) => original.includes(t))
      expect(presentInOriginal.length).toBeGreaterThan(0)

      for (const token of presentInOriginal) {
        expect(result.anonymized.includes(token), `leaked token: ${token} in ${name}`).toBe(false)
      }

      expect(result.matches.length).toBeGreaterThan(50)
      expect(result.entities.length).toBeGreaterThan(10)
      if (/\bdisp\d+\b/i.test(original)) {
        expect(result.entities.some((e) => e.category === 'user-id')).toBe(true)
      }
      if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(original)) {
        expect(result.entities.some((e) => e.category === 'ip')).toBe(true)
      }
    })
  }

  it('covers every must-not-leak category across the fixture set', () => {
    const combined = FIXTURE_LOGS.map((n) => readFixtureLog(n)).join('\n')
    for (const [category, tokens] of Object.entries(MUST_NOT_LEAK)) {
      const hits = tokens.filter((t) => combined.includes(t))
      expect(hits.length, `category ${category} should appear in fixtures`).toBeGreaterThan(0)
    }
  })

  it('is deterministic across repeated analyze()', () => {
    const original = readFixtureLog('template-edge.log')
    const a = analyze(original)
    const b = analyze(original)
    expect(a.anonymized).toBe(b.anonymized)
    expect(a.matches.map((m) => [m.start, m.end, m.entityKey])).toEqual(
      b.matches.map((m) => [m.start, m.end, m.entityKey]),
    )
  })
})
