import { describe, expect, it } from 'vitest'
import {
  createReplacementCounters,
  nextReplacement,
} from '../../src/engine/replacements.ts'
import { createOffsetMap } from '../../src/engine/offsetMap.ts'
import { analyze } from '../../src/engine/analyze.ts'
import { FLAG_ENABLED } from '../../src/engine/packedMatchIndex.ts'

describe('replacements', () => {
  it('numbers categories in first-occurrence order', () => {
    const c = createReplacementCounters()
    expect(nextReplacement('ip', '1.1.1.1', c)).toBe('10.255.90.1')
    expect(nextReplacement('ip', '2.2.2.2', c)).toBe('10.255.90.2')
    expect(nextReplacement('hostname', 'a.local', c)).toBe('host-1.example.invalid')
    expect(nextReplacement('person', 'A B', c)).toBe('Person 1')
    expect(nextReplacement('user-id', 'disp1', c)).toBe('account-1')
    expect(nextReplacement('internal-id', 'MP_PRA', c)).toBe('MP_internal-1')
    expect(nextReplacement('internal-id', 'GRP_X', c)).toBe('GRP_internal-2')
    expect(nextReplacement('email', 'a@b.c', c)).toBe('user1@example.invalid')
  })
})

describe('offsetMap updateMatch', () => {
  it('updates fenwick deltas when a match length changes', () => {
    const text = 'aa10.1.1.1bb'
    const a = analyze(text)
    const map = createOffsetMap(a.packed, a.plan)
    const before = map.originalToOutput(text.length)
    expect(before).toBe(a.anonymized.length)

    // Simulate toggle-off: length delta → 0
    const i = 0
    expect((a.packed.flags[i]! & FLAG_ENABLED) !== 0).toBe(true)
    map.updateMatch(i, 0)
    expect(map.originalToOutput(text.length)).toBe(text.length)
  })
})
