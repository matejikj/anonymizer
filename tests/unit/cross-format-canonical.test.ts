import { describe, expect, it } from 'vitest'
import {
  canonicalizeCrossFormatCategory,
  crossFormatRegistryKey,
  crossFormatRegistryKeyFromIdentity,
  constraintsCompatible,
  CROSS_FORMAT_CATEGORY_CONTRACTS,
  assertCrossFormatContractComplete,
} from '../../src/mapping/crossFormat'

describe('Stage 25 cross-format golden canonicalization', () => {
  it('normalizes IPv4/IPv6/MAC across spelling variants', () => {
    expect(canonicalizeCrossFormatCategory('ipv4', '10.00.00.01', 'text')).toBe('10.0.0.1')
    // T33 — canonical IPv6 is expanded 8-hextet form (leading zeros stripped per hextet).
    expect(canonicalizeCrossFormatCategory('ipv6', '2001:0db8::1', 'pcap')).toBe('2001:db8:0:0:0:0:0:1')
    expect(canonicalizeCrossFormatCategory('mac', '00-1A-2b-3C-4d-5E', 'text')).toBe('00:1a:2b:3c:4d:5e')
  })

  it('normalizes hostname spelling variants', () => {
    expect(canonicalizeCrossFormatCategory('hostname', 'Host.Example.COM.', 'text')).toBe('host.example.com')
    expect(canonicalizeCrossFormatCategory('hostname', 'HOST.EXAMPLE.COM', 'pcap')).toBe('host.example.com')
  })

  it('requires transport context for port cross-format linking', () => {
    expect(canonicalizeCrossFormatCategory('port', ':5060', 'text')).toBeNull()
    expect(canonicalizeCrossFormatCategory('port', '5060', 'text')).toBeNull()
    expect(canonicalizeCrossFormatCategory('port', 'udp/5060', 'text')).toBe('udp/5060')
    expect(canonicalizeCrossFormatCategory('port', 'tcp/443', 'pcap')).toBe('tcp/443')
  })

  it('uses category/version domain separation in registry keys', () => {
    const ipv4Key = crossFormatRegistryKey('ipv4', '10.0.0.1')
    const ipv6Key = crossFormatRegistryKey('ipv6', '10.0.0.1')
    expect(ipv4Key).not.toBe(ipv6Key)
    expect(ipv4Key).toContain('cf:v1:ipv4:')
  })

  it('links text ip and pcap ipv4 to the same cross-format key', () => {
    const textKey = crossFormatRegistryKeyFromIdentity('ip', '10.0.0.5', { kind: 'ipv4-wire' })
    const pcapKey = crossFormatRegistryKeyFromIdentity('ipv4', '10.0.0.5', { kind: 'ipv4-wire' })
    expect(textKey).toBe(pcapKey)
  })

  it('T45 — phone E.164 / national / 00 separation', () => {
    expect(canonicalizeCrossFormatCategory('phone', '+420 777 123 456', 'text')).toBe('+420777123456')
    expect(canonicalizeCrossFormatCategory('phone', 'tel:+420777123456', 'pcap')).toBe('+420777123456')
    expect(canonicalizeCrossFormatCategory('phone', '777123456', 'text')).toBe('777123456')
    // 00… without dialing context stays a separate national/international-prefix key.
    expect(canonicalizeCrossFormatCategory('phone', '00420777123456', 'text')).toBe('00420777123456')
    expect(canonicalizeCrossFormatCategory('phone', '+420777123456', 'text')).not.toBe(
      canonicalizeCrossFormatCategory('phone', '00420777123456', 'text'),
    )
  })

  it('T45 — email domain casefold; user principal keeps realm type', () => {
    expect(canonicalizeCrossFormatCategory('email', 'Alice@Example.COM', 'text')).toBe('Alice@example.com')
    expect(canonicalizeCrossFormatCategory('user', 'alice', 'text')).toBe('local:alice')
    expect(canonicalizeCrossFormatCategory('user', 'CORP\\Alice', 'text')).toBe('nt:corp:alice')
    expect(canonicalizeCrossFormatCategory('user', 'alice@RADIUS', 'pcap')).toBe('realm:radius:alice')
    // Mailbox-shaped @domain is not a user principal.
    expect(canonicalizeCrossFormatCategory('user', 'alice@example.com', 'text')).toBeNull()
  })

  it('T45 — sip:+ and tel:+ share phone key; bare sip:1234 stays user', () => {
    const sipPlus = crossFormatRegistryKeyFromIdentity('sip-user', '+420777123456', {
      kind: 'text-ascii',
      byteLength: 13,
    })
    const telPlus = crossFormatRegistryKeyFromIdentity('sip-phone', '+420777123456', {
      kind: 'text-ascii',
      byteLength: 13,
    })
    expect(sipPlus).toBe(telPlus)
    expect(sipPlus).toContain('cf:v1:phone:')

    const bareSip = crossFormatRegistryKeyFromIdentity('sip-user', '1234', {
      kind: 'text-ascii',
      byteLength: 4,
    })
    const bareTel = crossFormatRegistryKeyFromIdentity('sip-phone', '1234', {
      kind: 'text-ascii',
      byteLength: 4,
    })
    expect(bareSip).toContain('cf:v1:user:')
    expect(bareTel).toContain('cf:v1:phone:')
    expect(bareSip).not.toBe(bareTel)
  })
})

describe('Stage 25 representation compatibility', () => {
  it('returns shared alias for compatible wire constraints', () => {
    const result = constraintsCompatible('ipv4', { kind: 'ipv4-wire' }, { kind: 'ipv4-wire' })
    expect(result.compatible).toBe(true)
    if (result.compatible) expect(result.sharedAlias).toBe(true)
  })

  it('returns distinct representation aliases for hostname length conflict', () => {
    const result = constraintsCompatible(
      'hostname',
      { kind: 'text-ascii', byteLength: 40 },
      { kind: 'hostname-ascii', labelCount: 2, maxLabelLength: 8 },
    )
    expect(result.compatible).toBe(true)
    if (result.compatible) expect(result.sharedAlias).toBe(false)
  })
})

describe('Stage 25 contract registry gate', () => {
  it('registers all required cross-format categories with full contract', () => {
    expect(() => assertCrossFormatContractComplete()).not.toThrow()
    expect(CROSS_FORMAT_CATEGORY_CONTRACTS.length).toBe(8)
    for (const contract of CROSS_FORMAT_CATEGORY_CONTRACTS) {
      expect(contract.canonicalizer).toBeTypeOf('function')
      expect(contract.representation).toBeTruthy()
      expect(contract.propertyTestId.length).toBeGreaterThan(0)
    }
  })
})
