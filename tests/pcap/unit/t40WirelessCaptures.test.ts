/**
 * T40 — radiotap/802.11 SSID+WPS, Bluetooth SMP, GSMTAP identify.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { LINKTYPE_IEEE802_11_RADIO, LINKTYPE_BLUETOOTH_HCI_H4 } from '../../../src/pcap/protocols/types'
import { SEMANTIC_SERVICE_PORTS } from '../../../src/pcap/anonymization/portPolicy'

function packetInput(data: Uint8Array, linkType: number) {
  return {
    index: 0,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

/** Minimal radiotap: ver=0, len=8, present=0 (no fields). */
function radiotapEmpty(): Uint8Array {
  return new Uint8Array([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
}

function buildBeaconWithSsid(ssid: string): Uint8Array {
  const ssidBytes = new TextEncoder().encode(ssid)
  // 802.11 mgmt beacon header 24 + fixed 12 + IE SSID + WPS vendor IE
  const wpsVal = new Uint8Array([0x00, 0x50, 0xf2, 0x04, ...new TextEncoder().encode('SERIALCANARY')])
  const body = new Uint8Array(12 + 2 + ssidBytes.length + 2 + wpsVal.length)
  // fixed beacon params zeros
  body[0] = 0x64 // beacon interval low
  body[2] = 0x01 // cap
  let o = 12
  body[o++] = 0 // SSID IE
  body[o++] = ssidBytes.length
  body.set(ssidBytes, o)
  o += ssidBytes.length
  body[o++] = 221
  body[o++] = wpsVal.length
  body.set(wpsVal, o)

  const hdr = new Uint8Array(24)
  hdr[0] = 0x80 // beacon subtype 8, type mgmt
  hdr[1] = 0x00
  // addr1 broadcast
  hdr.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 4)
  // addr2 / bssid
  hdr.set([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], 10)
  hdr.set([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], 16)

  const frame = new Uint8Array(hdr.length + body.length)
  frame.set(hdr, 0)
  frame.set(body, hdr.length)
  return frame
}

describe('T40 registry', () => {
  it('registers GSMTAP handler, wireless family, port, engine 2.36.1', () => {
    expect(APPLICATION_HANDLER_ORDER.map((h) => h.id)).toContain('gsmtap')
    expect(familyForProtocol('ieee80211').familyId).toBe('wireless')
    expect(familyForProtocol('bluetooth-smp').familyId).toBe('wireless')
    expect(familyForProtocol('gsmtap').familyId).toBe('wireless')
    expect(SEMANTIC_SERVICE_PORTS.has(4729)).toBe(true)
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T40 radiotap/802.11', () => {
  it('maps SSID and masks WPS serial canary', () => {
    const rt = radiotapEmpty()
    const beacon = buildBeaconWithSsid('HomeNet-Canary')
    const data = new Uint8Array(rt.length + beacon.length)
    data.set(rt, 0)
    data.set(beacon, rt.length)
    const mapping = new SessionMapping(undefined, { seed: 't40-wifi' })
    const result = sanitizePacket(packetInput(data, LINKTYPE_IEEE802_11_RADIO), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'radiotap')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'ieee80211-ssid')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'ieee80211-wps')).toBe(true)
    const out = applyPatches(data, result)
    expect(latin1(out).includes('HomeNet-Canary')).toBe(false)
    expect(latin1(out).includes('SERIALCANARY')).toBe(false)
  })

  it('maps binary SSID octets without UTF-8 assumptions', () => {
    const ssid = new Uint8Array([0x48, 0x6f, 0x6d, 0x00, 0xff, 0x01])
    const hdr = new Uint8Array(24)
    hdr[0] = 0x80 // beacon
    hdr.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 4)
    hdr.set([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], 10)
    hdr.set([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], 16)
    const ie = new Uint8Array(2 + ssid.length)
    ie[0] = 0
    ie[1] = ssid.length
    ie.set(ssid, 2)
    const rt = radiotapEmpty()
    const beacon = new Uint8Array(hdr.length + ie.length)
    beacon.set(hdr, 0)
    beacon.set(ie, hdr.length)
    const data = new Uint8Array(rt.length + beacon.length)
    data.set(rt, 0)
    data.set(beacon, rt.length)
    const mapping = new SessionMapping(undefined, { seed: 't40-binary-ssid' })
    const result = sanitizePacket(packetInput(data, LINKTYPE_IEEE802_11_RADIO), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(data, result)
    expect([...out.subarray(rt.length + 24 + 12 + 2, rt.length + 24 + 12 + 2 + ssid.length)]).not.toEqual([
      ...ssid,
    ])
    expect(out.includes(0x00)).toBe(true)
    expect(out.includes(0xff)).toBe(true)
  })

  it('masks Probe Request SSID in high-privacy', () => {
    const ssid = new TextEncoder().encode('SecretCafe')
    const hdr = new Uint8Array(24)
    hdr[0] = 0x40 // probe request subtype 4
    hdr.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 4)
    hdr.set([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee], 10)
    hdr.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 16)
    const ie = new Uint8Array(2 + ssid.length)
    ie[0] = 0
    ie[1] = ssid.length
    ie.set(ssid, 2)
    const data = new Uint8Array(hdr.length + ie.length)
    data.set(hdr, 0)
    data.set(ie, hdr.length)
    const mapping = new SessionMapping(undefined, { seed: 't40-probe' })
    const result = sanitizePacket(packetInput(data, 105), HIGH_PRIVACY_POLICY, mapping)
    const out = applyPatches(data, result)
    expect(latin1(out).includes('SecretCafe')).toBe(false)
  })
})

describe('T40 Bluetooth SMP', () => {
  it('masks SMP L2CAP payload', () => {
    // HCI ACL: type=2, handle, len, L2CAP len, CID=0x0006, pairing confirm canary
    const canary = new TextEncoder().encode('SMPKEYCANARY!!!!') // 16
    const payload = new Uint8Array(1 + 4 + 4 + canary.length)
    payload[0] = 0x02 // ACL
    payload[1] = 0x00
    payload[2] = 0x20 // handle
    payload[3] = (4 + canary.length) & 0xff
    payload[4] = 0
    payload[5] = canary.length & 0xff // l2cap length
    payload[6] = 0
    payload[7] = 0x06 // CID SMP
    payload[8] = 0x00
    payload.set(canary, 9)
    const mapping = new SessionMapping(undefined, { seed: 't40-bt' })
    const result = sanitizePacket(packetInput(payload, LINKTYPE_BLUETOOTH_HCI_H4), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'bluetooth-smp')).toBe(true)
    const out = applyPatches(payload, result)
    expect(latin1(out).includes('SMPKEYCANARY!!!!')).toBe(false)
  })
})

describe('T40 GSMTAP', () => {
  it('preserves header and names payload unsupported:gsmtap-*', () => {
    const hdr = new Uint8Array(16)
    hdr[0] = 0x02 // version
    hdr[1] = 0x04 // hdr words (v2 ignores; we use 16)
    hdr[2] = 0x06 // tetra-i1
    hdr[3] = 0x00
    const pay = new TextEncoder().encode('TETRA-SSI-CANARY')
    const payload = new Uint8Array(hdr.length + pay.length)
    payload.set(hdr, 0)
    payload.set(pay, hdr.length)
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 4729, 4729, payload)
    const mapping = new SessionMapping(undefined, { seed: 't40-gsmtap' })
    const result = sanitizePacket(packetInput(frame, 1), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'gsmtap')).toBe(true)
    expect(result.coverage.some((c) => c.protocol.startsWith('unsupported:gsmtap-'))).toBe(true)
    const out = applyPatches(frame, result)
    expect(latin1(out).includes('TETRA-SSI-CANARY')).toBe(false)
  })
})
