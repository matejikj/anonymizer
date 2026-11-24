/**
 * T19 — LLDP / LACP / EAPOL structured L2 sanitizers.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { ETHERTYPE_LLDP } from '../../../src/pcap/sanitize/lldp'
import { ETHERTYPE_SLOW } from '../../../src/pcap/sanitize/lacp'
import { ETHERTYPE_EAPOL } from '../../../src/pcap/sanitize/eapol'

function packetInput(data: Uint8Array) {
  return {
    index: 0,
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

function ethFrame(etherType: number, payload: Uint8Array): Uint8Array {
  const buf = new Uint8Array(14 + payload.length)
  buf.set([0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e], 0) // LLDP multicast-ish
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = (etherType >> 8) & 0xff
  buf[13] = etherType & 0xff
  buf.set(payload, 14)
  return buf
}

function tlv(type: number, value: Uint8Array): Uint8Array {
  const len = value.length
  const hdr = (type << 9) | (len & 0x1ff)
  const out = new Uint8Array(2 + len)
  out[0] = (hdr >> 8) & 0xff
  out[1] = hdr & 0xff
  out.set(value, 2)
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((s, p) => s + p.length, 0)
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

describe('T19 registry', () => {
  it('bumps engine version and assigns L2 families', () => {
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
    expect(DIAGNOSTIC_POLICY.lldp).toBe(true)
    expect(DIAGNOSTIC_POLICY.lacp).toBe(true)
    expect(DIAGNOSTIC_POLICY.eapol).toBe(true)
    expect(familyForProtocol('lldp').familyId).toBe('lldp')
    expect(familyForProtocol('lldp-med').familyId).toBe('lldp')
    expect(familyForProtocol('lacp').familyId).toBe('lacp')
    expect(familyForProtocol('eapol').familyId).toBe('eapol')
    expect(familyForProtocol('eapol-key').familyId).toBe('eapol')
  })
})

describe('T19 LLDP', () => {
  it('maps System Name like CDP Device-ID hostname alias', () => {
    const sysName = new TextEncoder().encode('switch-canary-01')
    const chassis = new Uint8Array(7)
    chassis[0] = 4 // MAC subtype
    chassis.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 1)
    const portName = new TextEncoder().encode('Gi0/1')
    const port = new Uint8Array(1 + portName.length)
    port[0] = 5 // ifName
    port.set(portName, 1)
    const ttl = new Uint8Array([0x00, 0x78])
    const payload = concat(
      tlv(1, chassis),
      tlv(2, port),
      tlv(3, ttl),
      tlv(5, sysName),
      tlv(0, new Uint8Array(0)),
    )
    const frame = ethFrame(ETHERTYPE_LLDP, payload)
    const mapping = new SessionMapping(undefined, { seed: 't19-lldp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'lldp')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('switch-canary-01')).toBe(false)
    // Same session: CDP Device-ID and LLDP System Name share hostname key
    const hostAlias = mapping.get('hostname', 'switch-canary-01')
    expect(hostAlias).toBeTruthy()
    expect(hostAlias).not.toBe('switch-canary-01')
    expect(mapping.map('hostname', 'switch-canary-01')).toBe(hostAlias)
  })

  it('always masks LLDP-MED location (ELIN canary)', () => {
    const chassis = new Uint8Array(7)
    chassis[0] = 4
    chassis.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 1)
    const port = new Uint8Array([5, 0x47, 0x69, 0x30, 0x2f, 0x31])
    const ttl = new Uint8Array([0x00, 0x78])
    // Org TLV: OUI 00-12-BB, subtype 3 (location), ELIN canary
    const elin = new TextEncoder().encode('ELIN-CANARY-911-555')
    const med = new Uint8Array(4 + elin.length)
    med[0] = 0x00
    med[1] = 0x12
    med[2] = 0xbb
    med[3] = 3
    med.set(elin, 4)
    const payload = concat(tlv(1, chassis), tlv(2, port), tlv(3, ttl), tlv(127, med), tlv(0, new Uint8Array(0)))
    const frame = ethFrame(ETHERTYPE_LLDP, payload)
    for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
      const mapping = new SessionMapping(undefined, { seed: 't19-med' })
      const result = sanitizePacket(packetInput(frame), policy, mapping)
      expect(result.coverage.some((c) => c.protocol === 'lldp-med')).toBe(true)
      const out = applyPatches(frame, result)
      expect(new TextDecoder('latin1').decode(out).includes('ELIN-CANARY-911-555')).toBe(false)
    }
  })
})

describe('T19 LACP', () => {
  it('maps Actor and Partner System MAC', () => {
    const actorSys = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]
    const partnerSys = [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
    const actorTlv = new Uint8Array(20)
    actorTlv[0] = 1 // Actor
    actorTlv[1] = 20
    actorTlv[2] = 0x00
    actorTlv[3] = 0x01 // priority
    actorTlv.set(actorSys, 4)
    // key/port/state left zero; reserved at 17..19
    actorTlv[17] = 0xca
    actorTlv[18] = 0xfe
    actorTlv[19] = 0x01
    const partnerTlv = new Uint8Array(20)
    partnerTlv[0] = 2
    partnerTlv[1] = 20
    partnerTlv.set(partnerSys, 4)
    const payload = concat(
      new Uint8Array([0x01, 0x01]), // LACP subtype + version
      actorTlv,
      partnerTlv,
      new Uint8Array([0x00, 0x00]), // terminator
    )
    const frame = ethFrame(ETHERTYPE_SLOW, payload)
    const mapping = new SessionMapping(undefined, { seed: 't19-lacp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'lacp')).toBe(true)
    const out = applyPatches(frame, result)
    const payloadOff = 14
    const actorMacOut = out.subarray(payloadOff + 2 + 4, payloadOff + 2 + 10)
    const partnerMacOut = out.subarray(payloadOff + 2 + 20 + 4, payloadOff + 2 + 20 + 10)
    expect([...actorMacOut]).not.toEqual(actorSys)
    expect([...partnerMacOut]).not.toEqual(partnerSys)
    // reserved canary cleared
    expect(out[payloadOff + 2 + 17]).not.toBe(0xca)
  })
})

describe('T19 EAPOL', () => {
  it('maps EAP Identity and masks MD5 challenge', () => {
    const identity = new TextEncoder().encode('alice@corp.example')
    const eapId = new Uint8Array(5 + identity.length)
    eapId[0] = 2 // Response
    eapId[1] = 1 // id
    const idLen = 5 + identity.length
    eapId[2] = (idLen >> 8) & 0xff
    eapId[3] = idLen & 0xff
    eapId[4] = 1 // Identity
    eapId.set(identity, 5)
    const eapolId = new Uint8Array(4 + eapId.length)
    eapolId[0] = 2 // version
    eapolId[1] = 0 // EAP-Packet
    eapolId[2] = (eapId.length >> 8) & 0xff
    eapolId[3] = eapId.length & 0xff
    eapolId.set(eapId, 4)

    const md5 = new Uint8Array(5 + 17)
    md5[0] = 1 // Request
    md5[1] = 2
    md5[2] = 0
    md5[3] = 22
    md5[4] = 4 // MD5
    md5[5] = 16
    md5.set([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], 6)
    const eapolMd5 = new Uint8Array(4 + md5.length)
    eapolMd5[0] = 2
    eapolMd5[1] = 0
    eapolMd5[2] = (md5.length >> 8) & 0xff
    eapolMd5[3] = md5.length & 0xff
    eapolMd5.set(md5, 4)

    const mapping = new SessionMapping(undefined, { seed: 't19-eap' })
    const idFrame = ethFrame(ETHERTYPE_EAPOL, eapolId)
    const idResult = sanitizePacket(packetInput(idFrame), DIAGNOSTIC_POLICY, mapping)
    expect(idResult.coverage.some((c) => c.protocol === 'eap' || c.protocol === 'eapol')).toBe(true)
    const idOut = applyPatches(idFrame, idResult)
    expect(new TextDecoder('latin1').decode(idOut).includes('alice@corp.example')).toBe(false)

    const md5Frame = ethFrame(ETHERTYPE_EAPOL, eapolMd5)
    const md5Result = sanitizePacket(packetInput(md5Frame), HIGH_PRIVACY_POLICY, mapping)
    const md5Out = applyPatches(md5Frame, md5Result)
    expect([...md5Out.subarray(14 + 4 + 5, 14 + 4 + 5 + 17)]).not.toEqual([
      16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ])
  })

  it('masks EAPOL-Key nonce and MIC', () => {
    const body = new Uint8Array(95 + 8)
    body[0] = 2 // RSN key descriptor
    // key info / len / replay left zero
    const nonceOff = 1 + 12
    for (let i = 0; i < 32; i++) body[nonceOff + i] = 0xa0 + (i & 0xf)
    const micOff = nonceOff + 32 + 16 + 8 + 8
    for (let i = 0; i < 16; i++) body[micOff + i] = 0xb0 + i
    body[micOff + 16] = 0
    body[micOff + 17] = 8 // key data len
    for (let i = 0; i < 8; i++) body[micOff + 18 + i] = 0xc0 + i

    const eapol = new Uint8Array(4 + body.length)
    eapol[0] = 2
    eapol[1] = 3 // EAPOL-Key
    eapol[2] = (body.length >> 8) & 0xff
    eapol[3] = body.length & 0xff
    eapol.set(body, 4)

    const frame = ethFrame(ETHERTYPE_EAPOL, eapol)
    const mapping = new SessionMapping(undefined, { seed: 't19-key' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'eapol-key')).toBe(true)
    const out = applyPatches(frame, result)
    const base = 14 + 4
    expect(out[base + nonceOff]).not.toBe(0xa0)
    expect(out[base + micOff]).not.toBe(0xb0)
    expect(out[base + micOff + 18]).not.toBe(0xc0)
  })
})
