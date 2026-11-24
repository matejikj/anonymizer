/**
 * T20 — Syslog / SNMP / NTP / TFTP structured sanitizers.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { UNSUPPORTED_PROTOCOL_NAMES } from '../../../src/pcap/sanitize/unsupportedIdentification'
import { createPayloadTimeSession } from '../../../src/pcap/kernel/payloadTimeCodec'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { sanitizeSyslog } from '../../../src/pcap/sanitize/syslog'
import { sanitizeSnmp } from '../../../src/pcap/sanitize/snmp'
import { sanitizeNtp } from '../../../src/pcap/sanitize/ntp'
import { sanitizeTftp } from '../../../src/pcap/sanitize/tftp'

function packetInput(data: Uint8Array, index = 0) {
  return {
    index,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function ascii(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

describe('T20 registry / families', () => {
  it('registers handlers and promotes families off unsupported', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('syslog')
    expect(ids).toContain('snmp')
    expect(ids).toContain('ntp')
    expect(ids).toContain('tftp')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('snmp')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('syslog')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('ntp')
    expect(familyForProtocol('syslog').familyId).toBe('logging')
    expect(familyForProtocol('snmp').familyId).toBe('management')
    expect(familyForProtocol('ntp').familyId).toBe('management')
    expect(familyForProtocol('tftp').familyId).toBe('management')
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
  })
})

describe('T20 syslog', () => {
  it('maps hostname and removes canary IPv4 from MSG in diagnostic', () => {
    const msg = ascii('<14>Jan  1 12:00:00 host-canary app: peer 203.0.113.77\n')
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 514, 514, msg)
    const mapping = new SessionMapping(undefined, { seed: 't20-syslog' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'syslog')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('host-canary')).toBe(false)
    expect(text.includes('203.0.113.77')).toBe(false)
  })
})

describe('T20 SNMP', () => {
  it('masks community string in v2c GetRequest', () => {
    // SEQUENCE { INTEGER 1, OCTET STRING "public", GetRequest-PDU … minimal }
    // SEQUENCE { version=1, community="public", GetRequest-PDU {…, varbind-list empty} }
    const pdu = new Uint8Array([
      0x30, 0x18,
      0x02, 0x01, 0x01, // version 1 (v2c)
      0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // "public"
      0xa0, 0x0b, // get-request len=11
      0x02, 0x01, 0x01,
      0x02, 0x01, 0x00,
      0x02, 0x01, 0x00,
      0x30, 0x00,
    ])
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 161, 161, pdu)
    const mapping = new SessionMapping(undefined, { seed: 't20-snmp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'snmp' && c.status === 'covered')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('public')).toBe(false)
  })
})

describe('T20 NTP', () => {
  it('maps IPv4 refid and does not leave original address bytes', () => {
    const ntp = new Uint8Array(48)
    ntp[0] = 0x1c // vn=3 mode=4
    ntp[1] = 2 // stratum 2
    // refid 10.1.2.3
    ntp[12] = 10
    ntp[13] = 1
    ntp[14] = 2
    ntp[15] = 3
    // non-zero transmit timestamp
    ntp[40] = 0xe5
    ntp[41] = 0x00
    ntp[42] = 0x00
    ntp[43] = 0x01
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 123, 123, ntp)
    const mapping = new SessionMapping(undefined, { seed: 't20-ntp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ntp')).toBe(true)
    const out = applyPatches(frame, result)
    const payloadOff = 14 + 20 + 8
    // Topology-preserving map may keep 10/8; require the full refid to change.
    expect([
      out[payloadOff + 12],
      out[payloadOff + 13],
      out[payloadOff + 14],
      out[payloadOff + 15],
    ]).not.toEqual([10, 1, 2, 3])
  })
})

describe('T20 TFTP', () => {
  it('masks DATA payload and maps RRQ filename', () => {
    const rrq = new Uint8Array([
      0x00, 0x01,
      ...ascii('secret-config.cfg'),
      0x00,
      ...ascii('octet'),
      0x00,
    ])
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 69, 12_000, rrq)
    const mapping = new SessionMapping(undefined, { seed: 't20-tftp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'tftp')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('secret-config.cfg')).toBe(false)

    const dataPkt = new Uint8Array([0x00, 0x03, 0x00, 0x01, ...ascii('PASSWORD=canary')])
    const dataFrame = buildEthIpUdp([10, 0, 0, 2], [10, 0, 0, 1], 12_000, 69, dataPkt)
    const r2 = sanitizePacket(packetInput(dataFrame), HIGH_PRIVACY_POLICY, mapping)
    const out2 = applyPatches(dataFrame, r2)
    expect(new TextDecoder('latin1').decode(out2).includes('PASSWORD=canary')).toBe(false)
  })
})

describe('T20 unit facades', () => {
  it('sanitize helpers claim on signature without throw', () => {
    const mapping = new SessionMapping(undefined, { seed: 't20-unit' })
    const pt = createPayloadTimeSession('relative', 't20-seed')
    pt.bindCaptureReference({
      ticks: 1_700_000_000_000n,
      unitsPerSecond: 1000n,
      offsetSeconds: 0n,
    })
    const syslog = ascii('<13>1 2024-01-01T00:00:00Z router - - - hello')
    const c1 = new PatchCollector(syslog.length)
    expect(
      sanitizeSyslog(syslog, 0, syslog.length, c1, mapping, undefined, 0, DIAGNOSTIC_POLICY, pt),
    ).not.toBeNull()
    const snmp = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00])
    const c2 = new PatchCollector(snmp.length)
    expect(sanitizeSnmp(snmp, 0, snmp.length, c2, mapping, undefined, 0)).not.toBeNull()
    const ntp = new Uint8Array(48)
    ntp[0] = 0x1b
    const c3 = new PatchCollector(48)
    expect(sanitizeNtp(ntp, 0, 48, c3, mapping, undefined, 0, pt)).not.toBeNull()
    const tftp = new Uint8Array([0x00, 0x01, 0x61, 0x00, 0x6f, 0x00])
    const c4 = new PatchCollector(tftp.length)
    expect(
      sanitizeTftp(tftp, 0, tftp.length, c4, mapping, undefined, 0, false, 69, 1234),
    ).not.toBeNull()
    for (const c of [c1, c2, c3, c4]) {
      c.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
    }
  })
})
