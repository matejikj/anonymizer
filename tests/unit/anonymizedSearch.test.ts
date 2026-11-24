import { describe, expect, it } from 'vitest'
import { analyze } from '../../src/engine/analyze.ts'
import { fenwickBuild } from '../../src/engine/fenwick.ts'
import { FLAG_ENABLED } from '../../src/engine/packedMatchIndex.ts'
import { transformWithPlan, type ReplacementPlan } from '../../src/engine/transform.ts'
import type { PackedMatchIndex } from '../../src/domain/types.ts'
import {
  findAnonymizedMatches,
  LARGE_FULL_TRANSFORM_CHARS,
} from '../../src/features/workspace/anonymizedSearch.ts'

function packOne(
  start: number,
  length: number,
  line: number,
): PackedMatchIndex {
  return {
    starts: new Uint32Array([start]),
    lengths: new Uint32Array([length]),
    lines: new Uint32Array([line]),
    entityIndexes: new Uint32Array([0]),
    flags: new Uint16Array([FLAG_ENABLED]),
  }
}

function planFor(replacements: Array<string | null>, originalLengths: number[]): ReplacementPlan {
  const lengthDeltas = new Int32Array(replacements.length)
  for (let i = 0; i < replacements.length; i++) {
    const r = replacements[i]
    lengthDeltas[i] = r == null ? 0 : r.length - (originalLengths[i] ?? 0)
  }
  return {
    replacements,
    lengthDeltas,
    fenwick: fenwickBuild(lengthDeltas),
  }
}

/** Prefix that forces the line-by-line large-document path. */
function largePrefix(extra = 64): string {
  return 'x'.repeat(LARGE_FULL_TRANSFORM_CHARS + extra)
}

describe('findAnonymizedMatches', () => {
  it('finds pseudonym text and maps back to original offsets', () => {
    const original = 'host 10.0.0.5 seen\n'
    const a = analyze(original)
    const ip = a.entities.find((e) => e.category === 'ip')
    expect(ip).toBeTruthy()
    const transformed = transformWithPlan(original, a.packed, a.plan)
    expect(transformed).toContain(ip!.replacement)

    const hits = findAnonymizedMatches(original, a.packed, a.plan, ip!.replacement, false)
    expect(hits.length).toBeGreaterThan(0)
    expect(original.slice(hits[0]!.from, hits[0]!.to)).toBe('10.0.0.5')
  })

  it('does not match original value when searching anonymized view', () => {
    const original = 'host 10.0.0.5 seen\n'
    const a = analyze(original)
    expect(findAnonymizedMatches(original, a.packed, a.plan, '10.0.0.5', false)).toHaveLength(0)
    expect(findAnonymizedMatches(original, a.packed, a.plan, 'seen', false).length).toBeGreaterThan(0)
  })
})

describe('findAnonymizedMatches — large document path', () => {
  it('finds unchanged text past LARGE_FULL_TRANSFORM_CHARS', () => {
    const prefix = largePrefix()
    const original = `${prefix}\nTAIL_MARKER_UNCHANGED\n`
    const empty: PackedMatchIndex = {
      starts: new Uint32Array(),
      lengths: new Uint32Array(),
      lines: new Uint32Array(),
      entityIndexes: new Uint32Array(),
      flags: new Uint16Array(),
    }
    const plan = planFor([], [])
    const hits = findAnonymizedMatches(original, empty, plan, 'TAIL_MARKER_UNCHANGED', true)
    expect(hits).toHaveLength(1)
    expect(original.slice(hits[0]!.from, hits[0]!.to)).toBe('TAIL_MARKER_UNCHANGED')
  })

  it('maps hit inside a longer pseudonym back to the original span', () => {
    const prefix = largePrefix()
    const token = 'AB'
    const line = `pre ${token} post\n`
    const original = prefix + '\n' + line
    const start = prefix.length + 1 + 'pre '.length
    const packed = packOne(start, token.length, 1)
    const longer = 'LONGPSEUDONYM'
    const plan = planFor([longer], [token.length])

    const hits = findAnonymizedMatches(original, packed, plan, 'PSEUDO', true)
    expect(hits.length).toBeGreaterThan(0)
    expect(hits[0]!.from).toBe(start)
    expect(hits[0]!.to).toBe(start)
  })

  it('maps hit inside a shorter pseudonym back to the original span', () => {
    const prefix = largePrefix()
    const token = 'LONGORIGINAL'
    const line = `pre ${token} post\n`
    const original = prefix + '\n' + line
    const start = prefix.length + 1 + 'pre '.length
    const packed = packOne(start, token.length, 1)
    const shorter = 'XY'
    const plan = planFor([shorter], [token.length])

    const hits = findAnonymizedMatches(original, packed, plan, 'XY', true)
    expect(hits).toHaveLength(1)
    expect(hits[0]!.from).toBe(start)
    expect(original.slice(hits[0]!.from, hits[0]!.from + token.length)).toBe(token)
  })

  it('finds a match that starts at a physical line boundary', () => {
    const prefix = largePrefix()
    const original = `${prefix}\nBOUNDARY_HIT rest of line\n`
    const empty: PackedMatchIndex = {
      starts: new Uint32Array(),
      lengths: new Uint32Array(),
      lines: new Uint32Array(),
      entityIndexes: new Uint32Array(),
      flags: new Uint16Array(),
    }
    const plan = planFor([], [])
    const hits = findAnonymizedMatches(original, empty, plan, 'BOUNDARY_HIT', true)
    expect(hits).toHaveLength(1)
    expect(hits[0]!.from).toBe(prefix.length + 1)
    expect(original.slice(hits[0]!.from, hits[0]!.to)).toBe('BOUNDARY_HIT')
  })

  it('respects case-sensitive and case-insensitive modes', () => {
    const prefix = largePrefix()
    const original = `${prefix}\nHelloCase\n`
    const empty: PackedMatchIndex = {
      starts: new Uint32Array(),
      lengths: new Uint32Array(),
      lines: new Uint32Array(),
      entityIndexes: new Uint32Array(),
      flags: new Uint16Array(),
    }
    const plan = planFor([], [])
    expect(findAnonymizedMatches(original, empty, plan, 'hellocase', true)).toHaveLength(0)
    const insensitive = findAnonymizedMatches(original, empty, plan, 'hellocase', false)
    expect(insensitive).toHaveLength(1)
    expect(original.slice(insensitive[0]!.from, insensitive[0]!.to)).toBe('HelloCase')
  })

  it('stops at maxMatches across many lines', () => {
    const prefix = largePrefix()
    const repeated = Array.from({ length: 40 }, () => 'hit_token_here\n').join('')
    const original = `${prefix}\n${repeated}`
    const empty: PackedMatchIndex = {
      starts: new Uint32Array(),
      lengths: new Uint32Array(),
      lines: new Uint32Array(),
      entityIndexes: new Uint32Array(),
      flags: new Uint16Array(),
    }
    const plan = planFor([], [])
    const hits = findAnonymizedMatches(original, empty, plan, 'hit_token', true, 7)
    expect(hits).toHaveLength(7)
  })

  it('returns the same original offsets after removing unused mapAnonOffsetInSlice param', () => {
    const prefix = largePrefix()
    const short = 'ip'
    const long = 'hostname'
    const line = `alpha ${short} beta ${long} gamma\n`
    const original = prefix + '\n' + line
    const base = prefix.length + 1
    const shortStart = base + 'alpha '.length
    const longStart = base + `alpha ${short} beta `.length
    const packed: PackedMatchIndex = {
      starts: new Uint32Array([shortStart, longStart]),
      lengths: new Uint32Array([short.length, long.length]),
      lines: new Uint32Array([1, 1]),
      entityIndexes: new Uint32Array([0, 1]),
      flags: new Uint16Array([FLAG_ENABLED, FLAG_ENABLED]),
    }
    const plan = planFor(['ZZZZZZ', 'Y'], [short.length, long.length])

    const longerHit = findAnonymizedMatches(original, packed, plan, 'ZZZZ', true)
    expect(longerHit[0]).toEqual({ from: shortStart, to: shortStart })

    const shorterHit = findAnonymizedMatches(original, packed, plan, 'Y', true)
    expect(shorterHit[0]!.from).toBe(longStart)

    const unchanged = findAnonymizedMatches(original, packed, plan, 'gamma', true)
    expect(original.slice(unchanged[0]!.from, unchanged[0]!.to)).toBe('gamma')
  })
})
