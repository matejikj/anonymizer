/**
 * Enterprise step 7 — STUN/TURN (XOR addresses, MI=MODIFIED, FINGERPRINT recalc),
 * RTP header extensions via SDP extmap, RTCP APP / SDES PRIV / BYE reason.
 */

import { describe, expect, it } from 'vitest'
import { SessionMapping, DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import {
  DIAGNOSTIC_POLICY,
  sanitizePacket,
  sanitizeRtcp,
  sanitizeRtpOrSrtp,
  PatchCollector,
} from '../../../src/pcap/sanitize'
import {
  STUN_ATTR,
  STUN_FINGERPRINT_XOR,
  STUN_MAGIC_COOKIE,
  looksLikeStun,
} from '../../../src/pcap/protocols/application/stun/classify'
import { crc32 } from '../../../src/pcap/recovery/codec/crc32'
import { resolveCryptographicIntegrity, CRYPTO_INTEGRITY_ISSUE } from '../../../src/pcap/trust'
import { collectExtmapIds } from '../../../src/pcap/protocols/application/sdp/attributes'
import { parseSdp } from '../../../src/pcap/protocols/application/sdp/parser'
import { buildSdpMediaEndpoints } from '../../../src/pcap/protocols/application/sdp/mediaModel'

function buildEthIpUdp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const total = 14 + 20 + 8 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + 8 + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 17
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const udp = 34
  buf[udp] = (srcPort >> 8) & 0xff
  buf[udp + 1] = srcPort & 0xff
  buf[udp + 2] = (dstPort >> 8) & 0xff
  buf[udp + 3] = dstPort & 0xff
  const udpLen = 8 + payload.length
  buf[udp + 4] = (udpLen >> 8) & 0xff
  buf[udp + 5] = udpLen & 0xff
  buf.set(payload, udp + 8)
  return buf
}

function apply(packet: Uint8Array, result: { patches: readonly { offset: number; data: Uint8Array }[] }): Uint8Array {
  const out = packet.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function u16(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
}

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff])
}

function pad4(len: number): number {
  return (len + 3) & ~3
}

function attr(type: number, value: Uint8Array): Uint8Array {
  const padded = pad4(value.length)
  const out = new Uint8Array(4 + padded)
  out.set(u16(type), 0)
  out.set(u16(value.length), 2)
  out.set(value, 4)
  return out
}

function xorIpv4(ip: number[]): Uint8Array {
  return new Uint8Array([
    ip[0]! ^ ((STUN_MAGIC_COOKIE >>> 24) & 0xff),
    ip[1]! ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xff),
    ip[2]! ^ ((STUN_MAGIC_COOKIE >>> 8) & 0xff),
    ip[3]! ^ (STUN_MAGIC_COOKIE & 0xff),
  ])
}

function buildXorMappedAddress(ip: number[], port: number): Uint8Array {
  const xPort = (port ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xffff)) & 0xffff
  const value = new Uint8Array(8)
  value[1] = 0x01 // IPv4
  value.set(u16(xPort), 2)
  value.set(xorIpv4(ip), 4)
  return attr(STUN_ATTR.XOR_MAPPED_ADDRESS, value)
}

/** Binding Success with XOR-MAPPED, USERNAME, dummy MI, FINGERPRINT. */
function buildIceStunBindingSuccess(opts: {
  mappedIp: number[]
  mappedPort: number
  username: string
}): Uint8Array {
  const txn = new Uint8Array(12)
  for (let i = 0; i < 12; i++) txn[i] = i + 1

  const usernameBytes = new Uint8Array([...opts.username].map((c) => c.charCodeAt(0)))
  const miValue = new Uint8Array(20).fill(0xab)
  const bodyParts = [
    buildXorMappedAddress(opts.mappedIp, opts.mappedPort),
    attr(STUN_ATTR.USERNAME, usernameBytes),
    attr(STUN_ATTR.MESSAGE_INTEGRITY, miValue),
  ]
  // Placeholder fingerprint — overwritten after length is known.
  const fpPlaceholder = attr(STUN_ATTR.FINGERPRINT, new Uint8Array(4))
  const bodyLen = bodyParts.reduce((s, p) => s + p.length, 0) + fpPlaceholder.length

  const msg = new Uint8Array(20 + bodyLen)
  // Binding Success Response = 0x0101
  msg[0] = 0x01
  msg[1] = 0x01
  msg.set(u16(bodyLen), 2)
  msg.set(u32(STUN_MAGIC_COOKIE), 4)
  msg.set(txn, 8)
  let pos = 20
  for (const part of bodyParts) {
    msg.set(part, pos)
    pos += part.length
  }
  const fpAttrStart = pos
  msg.set(u16(STUN_ATTR.FINGERPRINT), pos)
  msg.set(u16(4), pos + 2)
  const crc = crc32(msg.subarray(0, fpAttrStart))
  const fp = (crc ^ STUN_FINGERPRINT_XOR) >>> 0
  msg.set(u32(fp), pos + 4)
  return msg
}

function decodeXorMappedIpv4(stunMsg: Uint8Array): number[] | null {
  let pos = 20
  const end = 20 + ((stunMsg[2]! << 8) | stunMsg[3]!)
  while (pos + 4 <= end) {
    const type = (stunMsg[pos]! << 8) | stunMsg[pos + 1]!
    const len = (stunMsg[pos + 2]! << 8) | stunMsg[pos + 3]!
    const valueStart = pos + 4
    if (type === STUN_ATTR.XOR_MAPPED_ADDRESS && len >= 8 && stunMsg[valueStart + 1] === 0x01) {
      const x = stunMsg.subarray(valueStart + 4, valueStart + 8)
      return [
        x[0]! ^ ((STUN_MAGIC_COOKIE >>> 24) & 0xff),
        x[1]! ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xff),
        x[2]! ^ ((STUN_MAGIC_COOKIE >>> 8) & 0xff),
        x[3]! ^ (STUN_MAGIC_COOKIE & 0xff),
      ]
    }
    pos = valueStart + pad4(len)
  }
  return null
}

function readFingerprint(stunMsg: Uint8Array): { attrStart: number; value: number } | null {
  let pos = 20
  const end = 20 + ((stunMsg[2]! << 8) | stunMsg[3]!)
  while (pos + 4 <= end) {
    const type = (stunMsg[pos]! << 8) | stunMsg[pos + 1]!
    const len = (stunMsg[pos + 2]! << 8) | stunMsg[pos + 3]!
    if (type === STUN_ATTR.FINGERPRINT && len === 4) {
      const v = stunMsg.subarray(pos + 4, pos + 8)
      return {
        attrStart: pos,
        value: ((v[0]! << 24) >>> 0) + (v[1]! << 16) + (v[2]! << 8) + v[3]!,
      }
    }
    pos = pos + 4 + pad4(len)
  }
  return null
}

describe('enterprise step 7 — STUN/TURN', () => {
  it('detects STUN via magic cookie', () => {
    const stun = buildIceStunBindingSuccess({
      mappedIp: [203, 0, 113, 50],
      mappedPort: 54320,
      username: 'ufrag:ufrag',
    })
    expect(looksLikeStun(stun, 0, stun.length)).toBe(true)
  })

  it('maps XOR-MAPPED-ADDRESS so original IP is gone; MI → MODIFIED; FINGERPRINT valid', () => {
    const originalIp = [203, 0, 113, 50]
    const stun = buildIceStunBindingSuccess({
      mappedIp: originalIp,
      mappedPort: 54320,
      username: 'alice:bob',
    })
    const pkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 54320, 3478, stun)
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' })
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    )

    expect(result.coverage.some((c) => c.protocol === 'stun')).toBe(true)
    expect(result.issues).toContain(CRYPTO_INTEGRITY_ISSUE.stunMi)
    expect(resolveCryptographicIntegrity({ issues: result.issues })).toBe('MODIFIED')

    const out = apply(pkt, result)
    const outStun = out.subarray(14 + 20 + 8)
    expect(looksLikeStun(outStun, 0, outStun.length)).toBe(true)

    const decoded = decodeXorMappedIpv4(outStun)
    expect(decoded).not.toBeNull()
    expect(decoded).not.toEqual(originalIp)

    // Original IP octets must not appear as a contiguous XOR-mapped plaintext in output.
    const origPlain = new Uint8Array(originalIp)
    const hay = outStun
    let found = false
    for (let i = 0; i + 4 <= hay.length; i++) {
      if (
        hay[i] === origPlain[0]
        && hay[i + 1] === origPlain[1]
        && hay[i + 2] === origPlain[2]
        && hay[i + 3] === origPlain[3]
      ) {
        found = true
        break
      }
    }
    expect(found).toBe(false)

    const fp = readFingerprint(outStun)
    expect(fp).not.toBeNull()
    const expected = (crc32(outStun.subarray(0, fp!.attrStart)) ^ STUN_FINGERPRINT_XOR) >>> 0
    expect(fp!.value).toBe(expected)

    // Dummy MI left in place (not recomputed).
    expect([...outStun].join(',')).toContain([0xab, 0xab, 0xab].join(','))
  })
})

describe('enterprise step 7 — RTP extmap + RTCP APP/PRIV', () => {
  it('parses SDP a=extmap IDs into media endpoints', () => {
    const text =
      'v=0\r\n'
      + 'o=- 1 1 IN IP4 10.0.0.1\r\n'
      + 's=-\r\n'
      + 'c=IN IP4 10.0.0.1\r\n'
      + 't=0 0\r\n'
      + 'm=audio 4000 RTP/AVP 0\r\n'
      + 'a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n'
      + 'a=extmap:3/sendrecv urn:ietf:params:rtp-hdrext:sdes:mid\r\n'
    const buf = new Uint8Array([...text].map((c) => c.charCodeAt(0)))
    const parsed = parseSdp(buf, 0, buf.length)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const ids = collectExtmapIds(parsed.session.sessionAttributes, parsed.session.media[0]!.attributes)
    expect([...ids].sort()).toEqual([1, 3])
    const eps = buildSdpMediaEndpoints(parsed.session, buf)
    expect(eps[0]?.headerExtensionIds).toEqual(expect.arrayContaining([1, 3]))
  })

  it('masks RTP one-byte extension values; unknown IDs tagged when extmap known', () => {
    // One-byte header: profile 0xBEDE, ext id=1 value "MID!", id=9 unknown value "XX"
    const extData = new Uint8Array([
      0x13, 0x4d, 0x49, 0x44, 0x21, // id=1, L=3 → 4 data bytes "MID!"
      0x91, 0x58, 0x58, // id=9, L=1 → 2 data bytes "XX"  (5+3=8, no pad needed)
    ])
    const headerLen = 12 + 4 + extData.length
    const rtp = new Uint8Array(headerLen + 8)
    rtp[0] = 0x90 // V=2, X=1
    rtp[1] = 0x00
    rtp[8] = 0x11
    rtp[9] = 0x22
    rtp[10] = 0x33
    rtp[11] = 0x44
    rtp[12] = 0xbe
    rtp[13] = 0xde
    rtp[14] = 0x00
    rtp[15] = extData.length / 4
    rtp.set(extData, 16)
    rtp.fill(0x7e, headerLen)

    const collector = new PatchCollector(rtp.length)
    const mapping = new SessionMapping(DEFAULT_MAPPING_CONFIG)
    const fps = new FingerprintSession()
    sanitizeRtpOrSrtp(rtp, 0, rtp.length, collector, mapping, undefined, 0, 'rtp', new Set([1]))
    collector.resolveDeferred({ mapping, fingerprints: fps })
    const out = rtp.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)

    expect(out[16]).toBe(0x13)
    expect(out[21]).toBe(0x91)
    expect([...out.subarray(17, 21)].join(',')).not.toBe([0x4d, 0x49, 0x44, 0x21].join(','))
    expect([...out.subarray(22, 24)].join(',')).not.toBe([0x58, 0x58].join(','))
    expect([...out.subarray(headerLen)].every((b) => b !== 0x7e)).toBe(true)
  })

  it('preserves RTCP APP 4-byte name and masks application data', () => {
    const app = new Uint8Array(20)
    app[0] = 0x80
    app[1] = 204
    app[2] = 0x00
    app[3] = 0x04 // words=4 → 20 bytes
    app.set([0xaa, 0xbb, 0xcc, 0xdd], 4)
    app.set([0x74, 0x65, 0x73, 0x74], 8) // "test"
    app.set([0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x21, 0x21], 12)

    const collector = new PatchCollector(app.length)
    const mapping = new SessionMapping(DEFAULT_MAPPING_CONFIG)
    const fps = new FingerprintSession()
    sanitizeRtcp(app, 0, app.length, collector, mapping, undefined, 0)
    collector.resolveDeferred({ mapping, fingerprints: fps })
    const out = app.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)

    expect([...out.subarray(8, 12)]).toEqual([0x74, 0x65, 0x73, 0x74])
    expect([...out.subarray(12)]).not.toEqual([0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x21, 0x21])
  })

  it('masks SDES PRIV values and BYE reason text', () => {
    const mapping = new SessionMapping(DEFAULT_MAPPING_CONFIG)
    const fps = new FingerprintSession()

    const sdesPkt = new Uint8Array(20)
    sdesPkt[0] = 0x81
    sdesPkt[1] = 202
    sdesPkt[2] = 0x00
    sdesPkt[3] = 0x04
    sdesPkt.set([0x11, 0x22, 0x33, 0x44], 4)
    sdesPkt[8] = 8 // PRIV
    sdesPkt[9] = 6
    sdesPkt.set([0x70, 0x72, 0x69, 0x76, 0x21, 0x21], 10)
    sdesPkt[16] = 0

    const c2 = new PatchCollector(sdesPkt.length)
    sanitizeRtcp(sdesPkt, 0, sdesPkt.length, c2, mapping, undefined, 1)
    c2.resolveDeferred({ mapping, fingerprints: fps })
    const outSdes = sdesPkt.slice()
    for (const p of c2.getPatches()) outSdes.set(p.data, p.offset)
    expect([...outSdes.subarray(10, 16)].join(',')).not.toBe(
      [0x70, 0x72, 0x69, 0x76, 0x21, 0x21].join(','),
    )

    const bye = new Uint8Array(16)
    bye[0] = 0x81
    bye[1] = 203
    bye[2] = 0x00
    bye[3] = 0x03
    bye.set([0x11, 0x22, 0x33, 0x44], 4)
    bye[8] = 7
    bye.set([0x67, 0x6f, 0x6f, 0x64, 0x62, 0x79, 0x65], 9)

    const c3 = new PatchCollector(bye.length)
    sanitizeRtcp(bye, 0, bye.length, c3, mapping, undefined, 2)
    c3.resolveDeferred({ mapping, fingerprints: fps })
    const outBye = bye.slice()
    for (const p of c3.getPatches()) outBye.set(p.data, p.offset)
    expect([...outBye.subarray(8)]).not.toEqual([
      0x07, 0x67, 0x6f, 0x6f, 0x64, 0x62, 0x79, 0x65,
    ])
  })
})
