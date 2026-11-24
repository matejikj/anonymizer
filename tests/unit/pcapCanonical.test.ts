import { describe, expect, it } from 'vitest'
import { canonicalizePcapIdentity, defaultWireConstraint } from '../../src/mapping/pcapCanonical'

describe('PCAP canonical identity', () => {
  it('normalizes IPv4 spelling variants to one key', () => {
    expect(canonicalizePcapIdentity('ipv4', '192.168.001.010')).toBe('192.168.1.10')
    expect(canonicalizePcapIdentity('ipv4', '192.168.1.10')).toBe('192.168.1.10')
  })

  it('normalizes MAC separators', () => {
    expect(canonicalizePcapIdentity('mac', 'AA-BB-CC-DD-EE-FF')).toBe('aa:bb:cc:dd:ee:ff')
    expect(canonicalizePcapIdentity('mac', 'aa:bb:cc:dd:ee:ff')).toBe('aa:bb:cc:dd:ee:ff')
  })

  it('normalizes hostname case and trailing dot', () => {
    expect(canonicalizePcapIdentity('hostname', 'Server.Example.COM.')).toBe('server.example.com')
  })

  it('rejects invalid port notation', () => {
    expect(canonicalizePcapIdentity('port', 'icmp/80')).toBeNull()
  })

  it('derives wire constraints for hostname label geometry', () => {
    const canonical = canonicalizePcapIdentity('hostname', 'a.bb.example.com')!
    const c = defaultWireConstraint('hostname', canonical)
    expect(c).toEqual({ kind: 'hostname-ascii', labelCount: 4, maxLabelLength: 7 })
  })
})
