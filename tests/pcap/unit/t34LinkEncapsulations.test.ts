/**
 * T34 — NULL/LOOP, PPPoE, MPLS, PAP password mask, Geneve/L2TP basics.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { listCatalogProtocols } from '../../../src/pcap/kernel/catalog'
import { LINKTYPE_NULL, LINKTYPE_LOOP } from '../../../src/pcap/protocols/types'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { buildEthIpUdp } from '../fixtures/voipCorpus'

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

describe('T34 registry', () => {
  it('registers NULL/LOOP and bumps engine version', () => {
    const ids = listCatalogProtocols().map((p) => p.id)
    expect(ids).toEqual(expect.arrayContaining(['null', 'loop']))
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
    expect(familyForProtocol('null-loop').familyId).toBe('network-headers')
    expect(familyForProtocol('pppoe').familyId).toBe('tunnels')
    expect(familyForProtocol('mpls').familyId).toBe('tunnels')
    expect(familyForProtocol('geneve').familyId).toBe('tunnels')
    expect(familyForProtocol('l2tp').familyId).toBe('tunnels')
    expect(familyForProtocol('erspan').familyId).toBe('tunnels')
  })
})

describe('T34 NULL/LOOP', () => {
  it('sanitizes macOS DLT_NULL IPv4 without link-unsupported', () => {
    // AF_INET=2 LE + minimal IPv4 (src 10.9.8.7)
    const pkt = new Uint8Array(4 + 20)
    pkt[0] = 2 // AF_INET LE
    pkt[4] = 0x45
    pkt[6] = 0
    pkt[7] = 20
    pkt[9] = 17 // UDP
    pkt.set([10, 9, 8, 7], 16)
    pkt.set([10, 0, 0, 2], 20)
    const mapping = new SessionMapping(undefined, { seed: 't34-null' })
    const result = sanitizePacket(packetInput(pkt, LINKTYPE_NULL), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'null-loop')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'unsupported:link-0')).toBe(false)
    expect(result.coverage.some((c) => c.protocol === 'ipv4')).toBe(true)
    const out = applyPatches(pkt, result)
    expect([...out.subarray(16, 20)]).not.toEqual([10, 9, 8, 7])
  })

  it('sanitizes DLT_LOOP IPv6 AF', () => {
    const pkt = new Uint8Array(4 + 40)
    // AF_INET6=30 network order
    pkt[3] = 30
    pkt[4] = 0x60
    pkt[10] = 17
    pkt[11] = 64 // hop
    // src
    pkt[20] = 0x20
    pkt[21] = 0x01
    pkt[22] = 0x0d
    pkt[23] = 0xb8
    const mapping = new SessionMapping(undefined, { seed: 't34-loop' })
    const result = sanitizePacket(packetInput(pkt, LINKTYPE_LOOP), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'null-loop')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'ipv6')).toBe(true)
  })
})

describe('T34 PPPoE / MPLS / PAP', () => {
  it('maps PPPoE session and continues IPv4', () => {
    const ip = new Uint8Array(20)
    ip[0] = 0x45
    ip[3] = 20
    ip[9] = 1
    ip.set([10, 1, 2, 3], 12)
    ip.set([10, 4, 5, 6], 16)
    const ppp = new Uint8Array(2 + ip.length)
    ppp[0] = 0x00
    ppp[1] = 0x21 // IPv4
    ppp.set(ip, 2)
    const pppoe = new Uint8Array(6 + ppp.length)
    pppoe[0] = 0x11
    pppoe[1] = 0 // session
    pppoe[2] = 0xab
    pppoe[3] = 0xcd // session id
    pppoe[4] = 0
    pppoe[5] = ppp.length
    pppoe.set(ppp, 6)
    const frame = new Uint8Array(14 + pppoe.length)
    frame.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    frame.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01], 6)
    frame[12] = 0x88
    frame[13] = 0x64
    frame.set(pppoe, 14)
    const mapping = new SessionMapping(undefined, { seed: 't34-pppoe' })
    const result = sanitizePacket(packetInput(frame, 1), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'pppoe')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'ipv4')).toBe(true)
    const out = applyPatches(frame, result)
    expect(out[14 + 2]).not.toBe(0xab) // session remapped
    expect([...out.subarray(14 + 6 + 2 + 12, 14 + 6 + 2 + 16)]).not.toEqual([10, 1, 2, 3])
  })

  it('unwraps MPLS to IPv4', () => {
    const ip = new Uint8Array(20)
    ip[0] = 0x45
    ip[3] = 20
    ip[9] = 1
    ip.set([10, 9, 8, 7], 12)
    ip.set([10, 0, 0, 1], 16)
    // One label, S=1, label=100
    const label = ((100 << 12) | (0 << 9) | (1 << 8) | 64) >>> 0
    const mpls = new Uint8Array(4 + ip.length)
    mpls[0] = (label >>> 24) & 0xff
    mpls[1] = (label >>> 16) & 0xff
    mpls[2] = (label >>> 8) & 0xff
    mpls[3] = label & 0xff
    mpls.set(ip, 4)
    const frame = new Uint8Array(14 + mpls.length)
    frame.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    frame.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02], 6)
    frame[12] = 0x88
    frame[13] = 0x47
    frame.set(mpls, 14)
    const mapping = new SessionMapping(undefined, { seed: 't34-mpls' })
    const result = sanitizePacket(packetInput(frame, 1), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'mpls')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'ipv4')).toBe(true)
    const out = applyPatches(frame, result)
    expect([...out.subarray(14 + 4 + 12, 14 + 4 + 16)]).not.toEqual([10, 9, 8, 7])
  })

  it('masks PAP password canary', () => {
    const peer = new TextEncoder().encode('alice')
    const pass = new TextEncoder().encode('PAP-SECRET-99')
    const body = new Uint8Array(4 + 1 + peer.length + 1 + pass.length)
    body[0] = 1 // Authenticate-Request
    body[1] = 1
    body[2] = 0
    body[3] = body.length
    body[4] = peer.length
    body.set(peer, 5)
    body[5 + peer.length] = pass.length
    body.set(pass, 6 + peer.length)
    const pkt = new Uint8Array(2 + body.length)
    pkt[0] = 0xc0
    pkt[1] = 0x23 // PAP
    pkt.set(body, 2)
    const mapping = new SessionMapping(undefined, { seed: 't34-pap' })
    const result = sanitizePacket(packetInput(pkt, 9), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(pkt, result)
    expect(new TextDecoder('latin1').decode(out).includes('PAP-SECRET-99')).toBe(false)
    expect(new TextDecoder('latin1').decode(out).includes('alice')).toBe(false)
  })
})

describe('T34 L2TP challenge', () => {
  it('masks L2TP Challenge AVP', () => {
    // Control: T=1 L=1, tunnel/session, then AVP Challenge
    const challenge = new TextEncoder().encode('CHAL-CANARY')
    const avpLen = 6 + challenge.length
    const hdr = new Uint8Array(2 + 2 + 4 + avpLen)
    hdr[0] = 0xc0 // T+L
    hdr[1] = 0x02 // version 2
    hdr[2] = 0
    hdr[3] = hdr.length
    hdr[4] = 0x12
    hdr[5] = 0x34 // tunnel
    hdr[6] = 0x56
    hdr[7] = 0x78 // session
    // AVP: M=1, len, vendor 0, attr 11 Challenge
    hdr[8] = 0x80
    hdr[9] = avpLen & 0xff
    hdr[10] = 0
    hdr[11] = 0
    hdr[12] = 0
    hdr[13] = 11
    hdr.set(challenge, 14)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1701, 1701, hdr)
    const mapping = new SessionMapping(undefined, { seed: 't34-l2tp' })
    const out = applyPatches(frame, sanitizePacket(packetInput(frame, 1), DIAGNOSTIC_POLICY, mapping))
    expect(new TextDecoder('latin1').decode(out).includes('CHAL-CANARY')).toBe(false)
  })
})
