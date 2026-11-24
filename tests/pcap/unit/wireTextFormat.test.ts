/**
 * C-1 regression coverage — text-embedded IPv4/IPv6 substitutions must always be valid,
 * exact-length literals, never containing literal 'x' filler in digit/hex slots.
 */

import { describe, expect, it } from 'vitest'
import { formatIpv4TextFromWire, formatTextAliasFromWire } from '../../../src/pcap/anonymization/wireTextFormat'

function isValidIpv4Literal(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false
    const n = Number(p)
    return n >= 0 && n <= 255
  })
}

describe('C-1: formatIpv4TextFromWire never corrupts output', () => {
  it('returns the mapped IP unchanged when the length already matches', () => {
    expect(formatIpv4TextFromWire('10.254.18.7', '10.254.18.7'.length)).toBe('10.254.18.7')
  })

  it('re-pads the same value when the target length is longer', () => {
    const out = formatIpv4TextFromWire('10.254.18.7', 14)
    expect(out.length).toBe(14)
    expect(isValidIpv4Literal(out)).toBe(true)
    expect(out.split('.').map(Number)).toEqual([10, 254, 18, 7])
  })

  it('produces a valid, exact-length IPv4 literal across the full realistic byte-length range, never containing "x"', () => {
    const mapped = ['10.254.18.7', '10.254.255.255', '198.51.1.1', '198.51.100.200']
    for (const ip of mapped) {
      for (let len = 7; len <= 15; len++) {
        const out = formatIpv4TextFromWire(ip, len)
        expect(out.length).toBe(len)
        expect(out).not.toMatch(/x/i)
        expect(isValidIpv4Literal(out)).toBe(true)
      }
    }
  })

  it('is deterministic (same mapped+length always yields the same text)', () => {
    const a = formatIpv4TextFromWire('10.254.18.7', 7)
    const b = formatIpv4TextFromWire('10.254.18.7', 7)
    expect(a).toBe(b)
  })
})

describe('C-1: formatTextAliasFromWire ipv4/ipv6 never leak literal x filler', () => {
  it('ipv4: handles a shorter original spelling without x corruption', () => {
    const out = formatTextAliasFromWire('ipv4', '10.254.200.201', 7, '1.2.3.4')
    expect(out.length).toBe(7)
    expect(out).not.toMatch(/x/i)
    expect(isValidIpv4Literal(out)).toBe(true)
  })

  it('ipv6: fills hex slots with real hex digits, never literal x', () => {
    const wireAlias = 'fd00:0:0:0:0:0:1234:5678'
    const originalSpelling = 'abcd:ef01:2345:6789:0:0:0:1' // different length, forces the fallback path
    const out = formatTextAliasFromWire('ipv6', wireAlias, originalSpelling.length, originalSpelling)
    expect(out.length).toBe(originalSpelling.length)
    expect(out).not.toMatch(/x/i)
    // every non-colon character must be a valid hex digit
    for (const ch of out) {
      if (ch === ':') continue
      expect(/[0-9a-fA-F]/.test(ch)).toBe(true)
    }
  })

  it('ipv6: does not echo the RFC 3849 documentation prefix shared by pseudonym and original', () => {
    // The pseudonym base for non-link-local IPv6 is literally "2001:db8:0:0" — a naive
    // fill-cycle that reuses the wire alias's own leading characters would silently
    // reproduce "2001:db8" whenever the original also happens to start with it (extremely
    // common in test fixtures and real captures using the documentation range).
    const wireAlias = '2001:db8:0:0:0:0:fa7d:733a'
    const originalSpelling = '2001:db8:dead:beef::1234'
    const out = formatTextAliasFromWire('ipv6', wireAlias, originalSpelling.length, originalSpelling)
    expect(out.length).toBe(originalSpelling.length)
    expect(out).not.toContain('2001:db8')
    expect(out).not.toContain('dead:beef')
  })
})
