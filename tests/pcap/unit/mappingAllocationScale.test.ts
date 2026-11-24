/**
 * T48 — allocation scale: no per-map used-set rebuild; roughly linear CPU to U=50k.
 */

import { performance } from 'node:perf_hooks'
import { describe, expect, it } from 'vitest'
import { DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping'
import { allocateExclusiveId } from '../../../src/pcap/anonymization/exclusiveIdAllocation'
import { createTestSessionMapping } from '../../../src/pcap/anonymization/testModeSeed'

function privateIpv4(i: number): string {
  // Unique in 10.0.0.0/8 for i ∈ [0, 2^24).
  return `10.${(i >>> 16) & 0xff}.${(i >>> 8) & 0xff}.${i & 0xff}`
}

function mapIpv4Batch(seed: string, count: number): { ms: number; aliases: Set<string> } {
  const m = createTestSessionMapping(seed)
  const aliases = new Set<string>()
  const t0 = performance.now()
  for (let i = 0; i < count; i++) {
    aliases.add(m.map('ipv4', privateIpv4(i)))
  }
  const ms = performance.now() - t0
  expect(m.overflow).toBe(false)
  expect(aliases.size).toBe(count)
  return { ms, aliases }
}

describe('mapping allocation scale (T48)', () => {
  it('denseProbe advances so near-exhaustion does not rescan from offset 0 every time', () => {
    const used = new Set<number>()
    for (let i = 0; i < 1000; i++) used.add(i)
    // Leave only high slots free: 1000..1023
    const denseProbe = { offset: 0 }
    const nextRandom = () => 0 // always miss into used[0]
    const a = allocateExclusiveId({
      used,
      min: 0,
      max: 1023,
      reject: () => false,
      nextRandom,
      randomAttempts: 1,
      denseProbe,
    })
    expect(a).toBe(1000)
    expect(denseProbe.offset).toBe(1001)
    used.add(a!)
    const b = allocateExclusiveId({
      used,
      min: 0,
      max: 1023,
      reject: () => false,
      nextRandom,
      randomAttempts: 1,
      denseProbe,
    })
    expect(b).toBe(1001)
    expect(denseProbe.offset).toBe(1002)
  })

  it('IPv4 U=1k/10k/50k stays bijective and grows roughly linearly', () => {
    const r1 = mapIpv4Batch('t48-scale-1k-seed-aaaaaaaa', 1_000)
    const r10 = mapIpv4Batch('t48-scale-10k-seed-bbbbbbbb', 10_000)
    const r50 = mapIpv4Batch('t48-scale-50k-seed-cccccccc', 50_000)

    // Soft linearity: 50× work should not exceed ~200× time (quadratic would be ~2500×).
    // Absolute floors absorb CI noise; ratios catch the O(U²) rebuild regression.
    expect(r1.ms).toBeGreaterThan(0)
    const ratio10 = r10.ms / Math.max(r1.ms, 0.05)
    const ratio50 = r50.ms / Math.max(r1.ms, 0.05)
    expect(ratio10).toBeLessThan(40)
    expect(ratio50).toBeLessThan(200)

    // Cross-batch aliases are independent sessions; within-batch already checked size.
    expect(r50.aliases.size).toBe(50_000)
  }, 120_000)

  it('IPv6 U=10k stays bijective without overflow under cardinality', () => {
    const m = createTestSessionMapping('t48-scale-ipv6-seed-dddddddd')
    const aliases = new Set<string>()
    for (let i = 0; i < 10_000; i++) {
      // Unique low-32 (and thus low-24) so T33 SN-group binding does not collapse the space.
      const hi = ((i >>> 16) & 0xffff).toString(16)
      const lo = (i & 0xffff).toString(16)
      const ip = `2001:db8:0:0:0:0:${hi}:${lo}`
      aliases.add(m.map('ipv6', ip))
    }
    expect(aliases.size).toBe(10_000)
    expect(m.overflow).toBe(false)
  }, 60_000)

  it('topology-preserving first candidate may collide; exclusive alloc still bijective', () => {
    const m = createTestSessionMapping('t48-topo-collide-seed-eeeeeeee', {
      ...DEFAULT_MAPPING_CONFIG,
      ip: 'topology-preserving',
    })
    const a = m.map('ipv4', '10.1.2.3')
    const b = m.map('ipv4', '10.1.2.4')
    expect(a).not.toBe(b)
    expect(a.startsWith('10.254.')).toBe(true)
    expect(b.startsWith('10.254.')).toBe(true)
    // Same /24 originals share target third octet even when the first candidate collides.
    expect(m.hasNoOriginalInOutput()).toBe(true)
  })
})
