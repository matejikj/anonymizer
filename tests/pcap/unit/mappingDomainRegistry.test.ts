/**
 * T48 — finite mapping domain registry completeness and exhaustion honesty.
 */

import { describe, expect, it } from 'vitest'
import {
  ENTITY_CATEGORIES,
  IPV4_BLOCK_DOMAIN_SIZE,
  MAPPING_DOMAIN_SPECS,
  assertMappingDomainsComplete,
  mappingDomainFor,
} from '../../../src/pcap/anonymization'
import { allocateExclusiveId } from '../../../src/pcap/anonymization/exclusiveIdAllocation'
import { createTestSessionMapping } from '../../../src/pcap/anonymization/testModeSeed'

describe('mappingDomainRegistry (T48)', () => {
  it('declares a domain for every EntityCategory', () => {
    expect(() => assertMappingDomainsComplete()).not.toThrow()
    expect(MAPPING_DOMAIN_SPECS.length).toBe(ENTITY_CATEGORIES.length)
    for (const c of ENTITY_CATEGORIES) {
      const spec = mappingDomainFor(c)
      expect(spec.category).toBe(c)
      expect(spec.exhaustion.length).toBeGreaterThan(0)
    }
  })

  it('documents IPv4 /16 finite capacity below the global 500k identity cap', () => {
    expect(IPV4_BLOCK_DOMAIN_SIZE).toBe(65_536)
    expect(mappingDomainFor('ipv4').domainSize).toBe(IPV4_BLOCK_DOMAIN_SIZE)
    expect(mappingDomainFor('ipv4').domainSize!).toBeLessThan(500_000)
  })

  it('IPv4 private /16 exhaustion sets overflow and returns a sentinel (never original)', () => {
    const m = createTestSessionMapping('t48-ipv4-exhaust-seed-0001')
    const originals: string[] = []
    for (let i = 0; i < IPV4_BLOCK_DOMAIN_SIZE; i++) {
      const ip = `10.0.${(i >> 8) & 0xff}.${i & 0xff}`
      originals.push(ip)
      const alias = m.map('ipv4', ip)
      expect(alias).toMatch(/^10\.254\./)
      expect(alias).not.toBe(ip)
    }
    expect(m.overflow).toBe(false)
    const overflowAlias = m.map('ipv4', '10.1.0.0')
    expect(m.overflow).toBe(true)
    expect(overflowAlias).toBe('0.0.0.0')
    expect(originals).not.toContain(overflowAlias)
  })

  it('VLAN / dense domain exhaustion returns null from allocator when used is full', () => {
    const used = new Set<number>()
    for (let id = 1; id <= 4094; id++) used.add(id)
    const slot = allocateExclusiveId({
      used,
      min: 1,
      max: 4094,
      reject: (n) => n === 7,
      nextRandom: () => 0,
      randomAttempts: 1,
    })
    expect(slot).toBeNull()
  })

  it('clone/adopt keep persistent slot indexes — abort leaves committed aliases stable', () => {
    const live = createTestSessionMapping('t48-clone-slots-seed-0001')
    const a = live.map('ipv4', '10.0.0.1')
    const b = live.map('ipv4', '10.0.0.2')
    const staging = live.clone()
    const c = staging.map('ipv4', '10.0.0.3')
    expect(c).not.toBe(a)
    expect(c).not.toBe(b)
    // Abort: do not adopt — live must not gain the staging allocation.
    expect(live.get('ipv4', '10.0.0.3')).toBeUndefined()
    expect(live.map('ipv4', '10.0.0.1')).toBe(a)
    expect(live.map('ipv4', '10.0.0.2')).toBe(b)
    // Commit: adopt staging into live — prior aliases stay, new ones appear.
    live.adoptFrom(staging)
    expect(live.map('ipv4', '10.0.0.1')).toBe(a)
    expect(live.map('ipv4', '10.0.0.3')).toBe(c)
  })

  it('unknown SessionMapping category fails closed to anon-overflow (not anon-N)', () => {
    const m = createTestSessionMapping('t48-unknown-cat-seed-0001')
    // T45 added email; probe a still-unknown category so fail-closed stays covered.
    const mapped = m.map('not-a-real-category' as never, 'user@example.com')
    expect(mapped).toBe('anon-overflow')
    expect(m.overflow).toBe(true)
  })
})
