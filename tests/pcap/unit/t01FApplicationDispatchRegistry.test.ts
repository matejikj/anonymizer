/**
 * T-01.F — application dispatch registry strangler parity with APPLICATION_HANDLER_ORDER.
 */
import { describe, expect, it } from 'vitest'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers.ts'
import {
  APPLICATION_DISPATCH_REGISTRY,
  TEMP_LEGACY_INLINE_HANDLERS,
} from '../../../src/pcap/sanitize/applicationDispatchRegistry.ts'

describe('T-01.F application dispatch registry', () => {
  it('every handler order id is registry or documented legacy inline', () => {
    for (const { id } of APPLICATION_HANDLER_ORDER) {
      const inRegistry = APPLICATION_DISPATCH_REGISTRY.has(id)
      const inLegacy = TEMP_LEGACY_INLINE_HANDLERS.has(id)
      expect(
        inRegistry || inLegacy,
        `handler ${id} must be in APPLICATION_DISPATCH_REGISTRY or TEMP_LEGACY_INLINE_HANDLERS`,
      ).toBe(true)
      expect(
        inRegistry && inLegacy,
        `handler ${id} cannot be both registry and legacy`,
      ).toBe(false)
    }
  })

  it('migrated handlers are registered (dns + dhcp/tls/T28 + voip/T51 + kernel-native onboarding)', () => {
    const migrated = [
      'dns',
      'dhcpv4',
      'dhcpv6',
      'tls',
      'ssh',
      'quic',
      'dtls',
      'ike',
      'openvpn',
      'wireguard',
      'sip',
      'csta',
      'ami',
      'ari',
      'mgcp',
      'h248',
      'rtsp',
      'iax2',
      'skinny',
      'h323',
      'stun',
      'lapd',
      'q931',
      'iua',
      'msrp',
      'bfcp',
      'zrtp',
      't38',
      'smpp',
      'rtp',
      'rtcp',
      'echo-udp-example',
      'rnd-dispatch-lite',
      'syslog',
      'snmp',
      'radius',
      'gtp',
      'http',
      'postgres',
      'mqtt',
      'dcerpc',
    ] as const
    for (const id of migrated) {
      expect(APPLICATION_DISPATCH_REGISTRY.has(id), id).toBe(true)
      expect(TEMP_LEGACY_INLINE_HANDLERS.has(id), id).toBe(false)
    }
  })

  it('registry covers 107/108 handlers (heuristic inline only)', () => {
    expect(APPLICATION_HANDLER_ORDER.length).toBe(108)
    expect(APPLICATION_DISPATCH_REGISTRY.size).toBe(107)
    expect([...TEMP_LEGACY_INLINE_HANDLERS]).toEqual(['heuristic'])
  })

  it('legacy set shrinks only by moving ids into the registry', () => {
    const orderIds = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    const legacyOnly = orderIds.filter((id) => TEMP_LEGACY_INLINE_HANDLERS.has(id))
    const registryOnly = orderIds.filter((id) => APPLICATION_DISPATCH_REGISTRY.has(id))
    expect(legacyOnly.length + registryOnly.length).toBe(orderIds.length)
    expect(registryOnly.length).toBe(APPLICATION_DISPATCH_REGISTRY.size)
  })
})
