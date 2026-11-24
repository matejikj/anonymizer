import { describe, expect, it } from 'vitest'
import { buildLineColumnMap, mapPhysicalLine } from '../../src/engine/columnMap.ts'
import { packResolvedMatches, entityKeyToIndex } from '../../src/engine/packedMatchIndex.ts'
import { buildReplacementPlan } from '../../src/engine/transform.ts'
import { analyze } from '../../src/engine/analyze.ts'
import { stepOccurrenceIndex } from '../../src/features/workspace/occurrences.ts'
import {
  loadPreference,
  savePreference,
  DEFAULT_SPLITTER_RATIO,
} from '../../src/persistence/preferencesRepository.ts'

describe('columnMap', () => {
  it('maps physical lines as identity', () => {
    expect(mapPhysicalLine(1)).toBe(1)
    expect(mapPhysicalLine(99)).toBe(99)
  })

  it('maps columns around a longer replacement', () => {
    const text = 'xx10.1.1.1yy'
    const result = analyze(text)
    const packed = packResolvedMatches(
      result.matches,
      entityKeyToIndex(result.entities),
      (k) => result.entitiesByKey.get(k)?.enabled ?? true,
    )
    const plan = buildReplacementPlan(packed, result.entities)
    const map = buildLineColumnMap(0, text.length, packed, plan)
    const ip = result.entities.find((e) => e.category === 'ip')!
    expect(ip.replacement.length).toBeGreaterThan('10.1.1.1'.length)

    // Before match: 1:1
    expect(map.originalToAnon(0)).toBe(0)
    expect(map.originalToAnon(2)).toBe(2)
    // Inside IP → start of replacement
    expect(map.originalToAnon(5)).toBe(2)
    // After match: account for length delta
    const delta = ip.replacement.length - '10.1.1.1'.length
    expect(map.originalToAnon(10)).toBe(2 + ip.replacement.length)
    expect(map.originalToAnon(text.length)).toBe(text.length + delta)
    expect(map.anonLength).toBe(text.length + delta)

    // Round-trip ends
    expect(map.anonToOriginal(0)).toBe(0)
    expect(map.anonToOriginal(map.anonLength)).toBe(text.length)
  })

  it('maps columns around a shorter fixed-style span', () => {
    // Synthesize a plan with a short replacement without going through IP generator.
    const text = 'AAABBBCCC'
    const packed = {
      starts: new Uint32Array([3]),
      lengths: new Uint32Array([3]),
      entityIndexes: new Uint32Array([0]),
      lines: new Uint32Array([1]),
      flags: new Uint16Array([1]),
    }
    const plan = {
      replacements: ['X'],
      lengthDeltas: new Int32Array([-2]),
      fenwick: new Int32Array(0),
    }
    const map = buildLineColumnMap(0, text.length, packed, plan)
    expect(map.originalToAnon(0)).toBe(0)
    expect(map.originalToAnon(3)).toBe(3)
    expect(map.originalToAnon(4)).toBe(3) // inside → start
    expect(map.originalToAnon(6)).toBe(4) // after short rep
    expect(map.originalToAnon(9)).toBe(7)
    expect(map.anonLength).toBe(7)
    expect(map.anonToOriginal(4)).toBe(6)
  })
})

describe('occurrence stepping', () => {
  it('wraps around', () => {
    expect(stepOccurrenceIndex(-1, 1, 5)).toBe(0)
    expect(stepOccurrenceIndex(-1, -1, 5)).toBe(4)
    expect(stepOccurrenceIndex(4, 1, 5)).toBe(0)
    expect(stepOccurrenceIndex(0, -1, 5)).toBe(4)
  })
})

describe('preferencesRepository', () => {
  it('stores wrap and splitter without throwing', () => {
    const mem = new Map<string, string>()
    const prev = globalThis.localStorage
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      value: {
        getItem: (k: string) => mem.get(k) ?? null,
        setItem: (k: string, v: string) => {
          mem.set(k, v)
        },
        removeItem: (k: string) => {
          mem.delete(k)
        },
      },
    })
    try {
      savePreference('wrap', true)
      expect(loadPreference('wrap', false)).toBe(true)
      savePreference('wrap', false)
      expect(loadPreference('wrap', true)).toBe(false)

      savePreference('splitterRatio', 0.35)
      expect(loadPreference('splitterRatio', DEFAULT_SPLITTER_RATIO)).toBe(0.35)
    } finally {
      Object.defineProperty(globalThis, 'localStorage', {
        configurable: true,
        value: prev,
      })
    }
  })
})
