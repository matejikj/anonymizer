import { describe, expect, it } from 'vitest'
import {
  canonicalizeIdentity,
  categoriesShareCanonical,
  identityMappingKey,
} from '../../src/mapping/canonicalize'
import { canonicalizeTextIdentity } from '../../src/mapping/textCanonical'
import { canonicalizePcapIdentity } from '../../src/mapping/pcapCanonical'

describe('Canonical identity', () => {
  it('normalizes IPv4 spelling variants to one binary key (text ip)', () => {
    expect(canonicalizeTextIdentity('ip', '192.168.001.010')).toBe('192.168.1.10')
    expect(canonicalizeTextIdentity('ip', '192.168.1.10')).toBe('192.168.1.10')
  })

  it('normalizes PCAP IPv4 the same way', () => {
    expect(canonicalizePcapIdentity('ipv4', '192.168.001.010')).toBe('192.168.1.10')
  })

  it('separates text ip from PCAP ipv4 category keys', () => {
    const raw = '10.0.0.1'
    const textKey = identityMappingKey('ip', canonicalizeTextIdentity('ip', raw)!)
    const pcapKey = identityMappingKey('ipv4', canonicalizePcapIdentity('ipv4', raw)!)
    expect(textKey).not.toBe(pcapKey)
  })

  it('does not share identity across categories for same spelling', () => {
    expect(categoriesShareCanonical('ip', 'hostname', '10.0.0.1')).toBe(false)
    expect(categoriesShareCanonical('email', 'hostname', 'user@example.com')).toBe(false)
  })

  it('normalizes hostname case and trailing dot for identity lookup', () => {
    expect(canonicalizeIdentity('hostname', 'Server.Example.COM.')).toBe('server.example.com')
    expect(canonicalizeTextIdentity('hostname', 'Server.Example.COM.')).toBe('server.example.com')
    expect(canonicalizePcapIdentity('hostname', 'Server.Example.COM.')).toBe('server.example.com')
  })

  it('normalizes MAC to six bytes', () => {
    expect(canonicalizeIdentity('mac', 'AA-BB-CC-DD-EE-FF')).toBe('aa:bb:cc:dd:ee:ff')
  })

  it('uses explicit email rules not blanket lowercasing of local part case preservation', () => {
    expect(canonicalizeTextIdentity('email', 'User.Name@Example.COM')).toBe('User.Name@example.com')
  })

  it('disambiguates text log ports from PCAP wire ports on shared category', () => {
    expect(canonicalizeIdentity('port', '5060')).toBe('5060')
    expect(canonicalizeIdentity('port', ':5060')).toBe('5060')
    expect(canonicalizeIdentity('port', 'udp/5060')).toBe('udp/5060')
    expect(canonicalizeIdentity('port', 'tcp/443')).toBe('tcp/443')
  })

  it('normalizes sip-phone preserving international + marker (T45)', () => {
    expect(canonicalizeTextIdentity('sip-phone', '+420 777 123 456')).toBe('+420777123456')
    expect(canonicalizeTextIdentity('sip-phone', '777123456')).toBe('777123456')
  })

  it('normalizes SIP wire identity categories', () => {
    expect(canonicalizeIdentity('sip-call-id', 'ABC@Host.Example')).toBe('ABC@host.example')
    expect(canonicalizeIdentity('sip-token', 'Z9hG4bK-abc')).toBe('z9hg4bk-abc')
    expect(canonicalizeIdentity('sip-user', 'Alice')).toBe('alice')
  })
})
