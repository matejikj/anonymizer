/**
 * T40 — SSID EntityCategory shared between 802.11 IE and RADIUS Called-Station suffix.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { canonicalizePcapIdentity } from '../../../src/mapping/pcapCanonical'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { LINKTYPE_IEEE802_11_RADIO } from '../../../src/pcap/protocols/types'
import {
  ssidCanonicalFromBytes,
  ssidWireBytesFromAlias,
} from '../../../src/pcap/sanitize/wireless/common'

function packetInput(data: Uint8Array, linkType = 1) {
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

function radiotapEmpty(): Uint8Array {
  return new Uint8Array([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00])
}

function buildBeaconWithSsid(ssid: string): Uint8Array {
  const ssidBytes = new TextEncoder().encode(ssid)
  const wpsVal = new Uint8Array([0x00, 0x50, 0xf2, 0x04, 0x00])
  const body = new Uint8Array(12 + 2 + ssidBytes.length + 2 + wpsVal.length)
  body[0] = 0x64
  body[2] = 0x01
  let o = 12
  body[o++] = 0
  body[o++] = ssidBytes.length
  body.set(ssidBytes, o)
  o += ssidBytes.length
  body[o++] = 221
  body[o++] = wpsVal.length
  body.set(wpsVal, o)

  const hdr = new Uint8Array(24)
  hdr[0] = 0x80
  hdr.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 4)
  hdr.set([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], 10)
  hdr.set([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], 16)

  const frame = new Uint8Array(hdr.length + body.length)
  frame.set(hdr, 0)
  frame.set(body, hdr.length)
  return frame
}

function radiusCalledStation(value: string): Uint8Array {
  const val = new TextEncoder().encode(value)
  const pkt = new Uint8Array(20 + 2 + val.length)
  pkt[0] = 1
  pkt[1] = 42
  const total = pkt.length
  pkt[2] = (total >> 8) & 0xff
  pkt[3] = total & 0xff
  pkt[20] = 30 // Called-Station-Id
  pkt[21] = 2 + val.length
  pkt.set(val, 22)
  return pkt
}

describe('T40 SSID category', () => {
  it('SessionMapping allocates ssid aliases', () => {
    const m = new SessionMapping(undefined, { seed: 'ssid-map-smoke' })
    const canon = ssidCanonicalFromBytes(new TextEncoder().encode('SecretCafe'), 0, 10)
    const alias = m.map('ssid', canon)
    expect(alias.length).toBeGreaterThan(0)
    expect(alias).not.toBe(canon)
    expect(m.get('ssid', canon)).toBe(alias)
  })

  it('canonicalizes ssid/<hex> (binary-safe, even hex length)', () => {
    const raw = ssidCanonicalFromBytes(new Uint8Array([0xff, 0x0a, 0x00]), 0, 3)
    expect(raw).toBe('ssid/ff0a00')
    expect(canonicalizePcapIdentity('ssid', raw)).toBe('ssid/ff0a00')
    expect(canonicalizePcapIdentity('ssid', 'SSID/FF0A00')).toBeNull()
    expect(canonicalizePcapIdentity('ssid', 'ssid/f')).toBeNull()
  })

  it('802.11 SSID and RADIUS Called-Station suffix share SessionMapping alias and wire bytes', () => {
    const ssidText = 'SecretCafe'
    const ssidBytes = new TextEncoder().encode(ssidText)
    const canon = ssidCanonicalFromBytes(ssidBytes, 0, ssidBytes.length)
    const mapping = new SessionMapping(undefined, { seed: 't40-ssid-radius-corr' })

    const rt = radiotapEmpty()
    const beacon = buildBeaconWithSsid(ssidText)
    const wifiData = new Uint8Array(rt.length + beacon.length)
    wifiData.set(rt, 0)
    wifiData.set(beacon, rt.length)
    const ssidOffWifi = rt.length + 24 + 12 + 2

    const wifiResult = sanitizePacket(packetInput(wifiData, LINKTYPE_IEEE802_11_RADIO), DIAGNOSTIC_POLICY, mapping)
    const wifiOut = applyPatches(wifiData, wifiResult)

    const radiusVal = `02:11:22:33:44:55:${ssidText}`
    const radiusPayload = radiusCalledStation(radiusVal)
    const radiusFrame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1812, 1812, radiusPayload)
    const radiusResult = sanitizePacket(packetInput(radiusFrame), DIAGNOSTIC_POLICY, mapping)
    const radiusOut = applyPatches(radiusFrame, radiusResult)

    const alias = mapping.get('ssid', canon)
    expect(alias).toBeDefined()
    expect(alias).not.toContain(ssidText)
    expect(mapping.map('ssid', canon)).toBe(alias)

    const expectedWire = ssidWireBytesFromAlias(alias!, ssidBytes.length)
    const wifiSsidWire = wifiOut.subarray(ssidOffWifi, ssidOffWifi + ssidBytes.length)
    expect(wifiSsidWire).toEqual(expectedWire)

    const ssidPatchRadius = radiusResult.patches.find((p) => p.data.length === ssidBytes.length)
    expect(ssidPatchRadius).toBeDefined()
    expect(ssidPatchRadius!.data).toEqual(expectedWire)
    expect(ssidPatchRadius!.data).toEqual(wifiSsidWire)
    expect(new TextDecoder('latin1').decode(radiusOut)).not.toContain(ssidText)
  })
})
