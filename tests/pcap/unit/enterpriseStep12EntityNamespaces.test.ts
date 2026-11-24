/**
 * Enterprise step 12 — entity namespaces, IP mode bound to profile, small-domain permutation.
 */

import { describe, expect, it } from 'vitest'
import {
  SessionMapping,
  DEFAULT_MAPPING_CONFIG,
  ENTITY_NAMESPACES,
  entityNamespaceFor,
  namespacesMustStayIsolated,
  ipModeForProfile,
  allocateExclusiveId,
} from '../../../src/pcap/anonymization'
import {
  DEFAULT_PCAP_LEVEL,
  levelToMapping,
  levelToMappingConfig,
  PCAP_ANONYMIZATION_LEVELS,
} from '../../../src/pcap/profile/presets'
import { buildDiagnosticResidualRisk } from '../../../src/pcap/trust'

function thirdOctet(ip: string): string {
  return ip.split('.')[2]!
}

describe('enterprise step 12 — namespaces + IP modes + small domains', () => {
  it('IP mode is bound to profile (no third UI toggle)', () => {
    expect(PCAP_ANONYMIZATION_LEVELS).toHaveLength(2)
    expect(ipModeForProfile('diagnostic')).toBe('topology-preserving')
    expect(ipModeForProfile('high-privacy')).toBe('privacy-preserving')
    expect(levelToMapping('diagnostic').ip).toBe('topology-preserving')
    expect(levelToMapping('high-privacy').ip).toBe('privacy-preserving')
    expect(levelToMappingConfig(DEFAULT_PCAP_LEVEL).ip).toBe('topology-preserving')
  })

  it('namespaces isolate SSRC from IP (no shared crypto pool)', () => {
    expect(entityNamespaceFor('ipv4')).toBe('IP')
    expect(entityNamespaceFor('ipv6')).toBe('IP')
    expect(entityNamespaceFor('ssrc')).toBe('SSRC')
    expect(entityNamespaceFor('sdp-session-id')).toBe('SDP_SESSION_ID')
    expect(namespacesMustStayIsolated('ipv4', 'ssrc')).toBe(true)
    expect(namespacesMustStayIsolated('ssrc', 'sdp-session-id')).toBe(true)
    expect(namespacesMustStayIsolated('ipv4', 'ipv6')).toBe(false)
    expect(ENTITY_NAMESPACES).toContain('VLAN')
    expect(ENTITY_NAMESPACES).toContain('PORT')
    expect(ENTITY_NAMESPACES).toContain('SIP_CALL_ID')

    const mapping = new SessionMapping(levelToMappingConfig('diagnostic'))
    // Exhaustively map many IPs — must not disturb SSRC allocation namespace.
    for (let i = 0; i < 64; i++) {
      mapping.map('ipv4', `10.1.${(i >> 8) & 0xff}.${i & 0xff}`)
    }
    const ssrcA = mapping.map('ssrc', '305419896')
    const ssrcB = mapping.map('ssrc', '305419896')
    expect(ssrcA).toBe(ssrcB)
    expect(ssrcA).not.toBe('305419896')
    // Fresh IP after SSRC still works in its own pool.
    const ip = mapping.map('ipv4', '10.9.9.9')
    expect(ip).not.toBe('10.9.9.9')
  })

  it('same canonical across wire forms resolves to one entity alias', () => {
    const mapping = new SessionMapping(levelToMappingConfig('diagnostic'))
    const wire = mapping.map('ipv4', '10.50.60.70')
    const again = mapping.aliasFor('ipv4', '10.50.60.70', { kind: 'ipv4-wire' })
    const text = mapping.aliasFor(
      'ipv4',
      '10.50.60.70',
      { kind: 'text-ascii', byteLength: wire.length },
      '10.50.60.70',
    )
    expect(again).toBe(wire)
    expect(mapping.get('ipv4', '10.50.60.70')).toBe(wire)
    // Text form is length-stable; still derived from the same mapped identity.
    expect(text.length).toBe(wire.length)
    expect(text).not.toContain('10.50.60.70')
  })

  it('diagnostic topology-preserving keeps /24 relationships', () => {
    const mapping = new SessionMapping({
      ...DEFAULT_MAPPING_CONFIG,
      ip: 'topology-preserving',
      ephemeralPorts: 'permute',
    })
    const a = mapping.map('ipv4', '192.168.40.10')
    const b = mapping.map('ipv4', '192.168.40.20')
    const c = mapping.map('ipv4', '192.168.41.10')
    // Same original /24 → same third octet in the mapped /16 block.
    expect(thirdOctet(a)).toBe(thirdOctet(b))
    // Different original /24 → typically different third octet.
    expect(thirdOctet(a) === thirdOctet(c) && a.split('.')[3] === c.split('.')[3]).toBe(false)
  })

  it('high-privacy privacy-preserving does not keep /24 relationships', () => {
    let shared = 0
    const trials = 48
    for (let t = 0; t < trials; t++) {
      const mapping = new SessionMapping({
        ...DEFAULT_MAPPING_CONFIG,
        ip: 'privacy-preserving',
        ephemeralPorts: 'permute',
      })
      const a = mapping.map('ipv4', '192.168.40.10')
      const b = mapping.map('ipv4', '192.168.40.20')
      if (thirdOctet(a) === thirdOctet(b)) shared++
    }
    // Topology mode would share on every trial; privacy should almost never.
    expect(shared).toBeLessThan(12)
  })

  it('VLAN/port use small-domain exclusive permutation (not FPE)', () => {
    const mapping = new SessionMapping({
      ...DEFAULT_MAPPING_CONFIG,
      vlan: 'map',
      ephemeralPorts: 'permute',
    })
    const v1 = mapping.map('vlan', '100')
    const v2 = mapping.map('vlan', '100')
    expect(v1).toBe(v2)
    expect(v1).not.toBe('100')
    const vOther = mapping.map('vlan', '200')
    expect(vOther).not.toBe(v1)

    const p1 = mapping.map('port', 'tcp/45000')
    const p2 = mapping.map('port', 'tcp/45000')
    expect(p1).toBe(p2)
    expect(p1).not.toBe('tcp/45000')

    // allocateExclusiveId is the shared small-domain primitive.
    const used = new Set<number>()
    const a = allocateExclusiveId({
      used,
      min: 1,
      max: 10,
      reject: (n) => n === 5,
      nextRandom: () => 3,
    })
    expect(a).not.toBeNull()
    expect(a).not.toBe(5)
  })

  it('diagnostic report residual risk includes topology; HP profile alone does not', () => {
    expect(
      buildDiagnosticResidualRisk({ profile: 'diagnostic' }).topology,
    ).toBe(true)
    expect(
      buildDiagnosticResidualRisk({ profile: 'high-privacy' }).topology,
    ).toBe(false)
  })
})
