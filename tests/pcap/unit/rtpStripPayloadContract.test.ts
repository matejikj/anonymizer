/**
 * @vitest-environment node
 *
 * Step 6 — diagnostic RTP/SRTP/RTCP transform:
 * preserve seq/ts/PT/marker and RTCP SR/RR stats; map SSRC; redact media/SDES.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { MediaFlowIndex } from '../../../src/pcap/discovery/mediaFlowIndex'
import {
  DIAGNOSTIC_POLICY,
  sanitizePacket,
} from '../../../src/pcap/sanitize'
import { parseRtpHeader } from '../../../src/pcap/protocols/application/rtp/classify'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

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

function readU32(buf: Uint8Array, off: number): number {
  return ((buf[off]! << 24) >>> 0) + (buf[off + 1]! << 16) + (buf[off + 2]! << 8) + buf[off + 3]!
}

function buildRtp(opts: {
  ssrc: number
  sequence: number
  timestamp: number
  marker?: boolean
  pt?: number
  payloadCanary?: number
  csrcs?: number[]
  oneByteExt?: { id: number; value: Uint8Array }
}): Uint8Array {
  const csrcs = opts.csrcs ?? []
  const hasExt = opts.oneByteExt !== undefined
  let extWords = 0
  let extBytes = new Uint8Array(0)
  if (opts.oneByteExt) {
    const v = opts.oneByteExt.value
    const raw = new Uint8Array(1 + v.length)
    raw[0] = ((opts.oneByteExt.id & 0x0f) << 4) | ((v.length - 1) & 0x0f)
    raw.set(v, 1)
    const pad = (4 - (raw.length % 4)) % 4
    extBytes = new Uint8Array(raw.length + pad)
    extBytes.set(raw)
    extWords = extBytes.length / 4
  }

  const headerLen = 12 + csrcs.length * 4 + (hasExt ? 4 + extWords * 4 : 0)
  const payloadLen = 16
  const buf = new Uint8Array(headerLen + payloadLen)
  buf[0] = 0x80 | (hasExt ? 0x10 : 0) | (csrcs.length & 0x0f)
  buf[1] = (opts.marker ? 0x80 : 0) | ((opts.pt ?? 0) & 0x7f)
  buf[2] = (opts.sequence >> 8) & 0xff
  buf[3] = opts.sequence & 0xff
  buf[4] = (opts.timestamp >>> 24) & 0xff
  buf[5] = (opts.timestamp >>> 16) & 0xff
  buf[6] = (opts.timestamp >>> 8) & 0xff
  buf[7] = opts.timestamp & 0xff
  buf[8] = (opts.ssrc >>> 24) & 0xff
  buf[9] = (opts.ssrc >>> 16) & 0xff
  buf[10] = (opts.ssrc >>> 8) & 0xff
  buf[11] = opts.ssrc & 0xff
  let pos = 12
  for (const c of csrcs) {
    buf[pos++] = (c >>> 24) & 0xff
    buf[pos++] = (c >>> 16) & 0xff
    buf[pos++] = (c >>> 8) & 0xff
    buf[pos++] = c & 0xff
  }
  if (hasExt) {
    buf[pos++] = 0xbe
    buf[pos++] = 0xde
    buf[pos++] = (extWords >> 8) & 0xff
    buf[pos++] = extWords & 0xff
    buf.set(extBytes, pos)
    pos += extBytes.length
  }
  const canary = opts.payloadCanary ?? 0xa5
  for (let i = pos; i < buf.length; i++) buf[i] = canary
  return buf
}

function buildSr(ssrc: number, reportSsrc: number): Uint8Array {
  const buf = new Uint8Array(52)
  buf[0] = 0x81
  buf[1] = 200
  buf[2] = 0
  buf[3] = 12
  buf[4] = (ssrc >>> 24) & 0xff
  buf[5] = (ssrc >>> 16) & 0xff
  buf[6] = (ssrc >>> 8) & 0xff
  buf[7] = ssrc & 0xff
  for (let i = 8; i < 28; i++) buf[i] = 0x10 + (i - 8)
  buf[28] = (reportSsrc >>> 24) & 0xff
  buf[29] = (reportSsrc >>> 16) & 0xff
  buf[30] = (reportSsrc >>> 8) & 0xff
  buf[31] = reportSsrc & 0xff
  buf[32] = 0x42
  buf[33] = 0x00
  buf[34] = 0x01
  buf[35] = 0x02
  buf[36] = 0x00
  buf[37] = 0x00
  buf[38] = 0x10
  buf[39] = 0x00
  buf[40] = 0x00
  buf[41] = 0x00
  buf[42] = 0x03
  buf[43] = 0xe8
  buf[44] = 0xaa
  buf[45] = 0xbb
  buf[46] = 0xcc
  buf[47] = 0xdd
  buf[48] = 0x11
  buf[49] = 0x22
  buf[50] = 0x33
  buf[51] = 0x44
  return buf
}

function buildSdes(ssrc: number, cname: string): Uint8Array {
  const cnameBytes = latin1(cname)
  const chunkLen = 4 + 2 + cnameBytes.length + 1
  const padded = chunkLen + ((4 - (chunkLen % 4)) % 4)
  const buf = new Uint8Array(4 + padded)
  buf[0] = 0x81
  buf[1] = 202
  const words = padded / 4
  buf[2] = (words >> 8) & 0xff
  buf[3] = words & 0xff
  buf[4] = (ssrc >>> 24) & 0xff
  buf[5] = (ssrc >>> 16) & 0xff
  buf[6] = (ssrc >>> 8) & 0xff
  buf[7] = ssrc & 0xff
  buf[8] = 1
  buf[9] = cnameBytes.length
  buf.set(cnameBytes, 10)
  return buf
}

function apply(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function seedSipMedia(
  mapping: SessionMapping,
  mediaFlowIndex: MediaFlowIndex,
  mediaPort: number,
): void {
  const sipIp = [192, 168, 1, 10]
  const sdp = [
    'v=0',
    'o=- 1 1 IN IP4 192.168.1.10',
    's=-',
    'c=IN IP4 192.168.1.10',
    't=0 0',
    `m=audio ${mediaPort} RTP/AVP 0 96`,
    '',
  ].join('\r\n')
  const sipText = [
    'INVITE sip:b@10.0.0.2 SIP/2.0',
    'Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK1',
    'From: <sip:a@192.168.1.10>;tag=t',
    'To: <sip:b@10.0.0.2>',
    'Call-ID: media-step6@host',
    'CSeq: 1 INVITE',
    'Content-Type: application/sdp',
    `Content-Length: ${sdp.length}`,
    '',
    sdp,
  ].join('\r\n')
  const sipPkt = buildEthIpUdp(sipIp, [10, 0, 0, 2], 5060, 5060, latin1(sipText))
  sanitizePacket(
    { index: 0, data: sipPkt, capturedLength: sipPkt.length, originalLength: sipPkt.length, linkType: 1 },
    DIAGNOSTIC_POLICY,
    mapping,
    { mediaFlowIndex },
  )
}

describe('SSRC mapping (step 6)', () => {
  it('never returns a fixed point and shares alias across map calls', () => {
    const mapping = new SessionMapping()
    const a = mapping.map('ssrc', '305419896')
    const b = mapping.map('ssrc', '305419896')
    expect(a).toBe(b)
    expect(a).not.toBe('305419896')
    expect(Number(a)).not.toBe(0x12345678)
  })
})

describe('RTP strip-payload (step 6)', () => {
  it('preserves V/M/PT/seq/ts, maps SSRC/CSRC, masks payload and extension values', () => {
    const ssrc = 0x12345678
    const csrc = 0x11111111
    const extValue = latin1('EXTSECRET!!')
    const rtp = buildRtp({
      ssrc,
      sequence: 0xabcd,
      timestamp: 0x10203040,
      marker: true,
      pt: 96,
      payloadCanary: 0xa5,
      csrcs: [csrc],
      oneByteExt: { id: 1, value: extValue },
    })
    const mapping = new SessionMapping()
    const mediaFlowIndex = new MediaFlowIndex()
    const mediaPort = 5004
    seedSipMedia(mapping, mediaFlowIndex, mediaPort)

    const rtpPkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40000, rtp)
    const result = sanitizePacket(
      { index: 1, data: rtpPkt, capturedLength: rtpPkt.length, originalLength: rtpPkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { mediaFlowIndex },
    )

    expect(result.drop).toBe(false)
    expect(result.truncatedLength).toBeUndefined()
    expect(result.coverage.some((c) => c.protocol === 'rtp' && c.status === 'redacted')).toBe(true)

    const out = apply(rtpPkt, result)
    const outRtp = out.subarray(14 + 20 + 8)
    const hdr = parseRtpHeader(outRtp, 0, outRtp.length)!
    expect(hdr.marker).toBe(true)
    expect(hdr.payloadType).toBe(96)
    expect(hdr.sequence).toBe(0xabcd)
    expect(hdr.timestamp).toBe(0x10203040)
    expect(hdr.ssrc).not.toBe(ssrc)
    expect(readU32(outRtp, 12)).not.toBe(csrc)
    expect([...outRtp.subarray(hdr.headerLength)].every((b) => b === 0xa5)).toBe(false)
    expect(new TextDecoder('latin1').decode(outRtp)).not.toContain('EXTSECRET')
  })

  it('maps the same SSRC alias in RTP and RTCP SR and keeps report stats', () => {
    const ssrc = 0x12345678
    const reportSsrc = 0xabcdef01
    const mapping = new SessionMapping()
    const mediaFlowIndex = new MediaFlowIndex()
    const mediaPort = 5004
    seedSipMedia(mapping, mediaFlowIndex, mediaPort)

    const rtp = buildRtp({ ssrc, sequence: 10, timestamp: 1000, payloadCanary: 0x5a })
    const rtpPkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort, 40000, rtp)
    const rtpResult = sanitizePacket(
      { index: 1, data: rtpPkt, capturedLength: rtpPkt.length, originalLength: rtpPkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { mediaFlowIndex },
    )
    const mappedSsrc = readU32(apply(rtpPkt, rtpResult), 14 + 20 + 8 + 8)

    const sr = buildSr(ssrc, reportSsrc)
    const rtcpPkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], mediaPort + 1, 40001, sr)
    const rtcpResult = sanitizePacket(
      { index: 2, data: rtcpPkt, capturedLength: rtcpPkt.length, originalLength: rtcpPkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { mediaFlowIndex },
    )
    const rtcpPayload = apply(rtcpPkt, rtcpResult).subarray(14 + 20 + 8)
    expect(readU32(rtcpPayload, 4)).toBe(mappedSsrc)
    expect(readU32(rtcpPayload, 28)).not.toBe(reportSsrc)
    expect([...rtcpPayload.subarray(8, 28)]).toEqual([...sr.subarray(8, 28)])
    expect(rtcpPayload[32]).toBe(0x42)
    expect(rtcpPayload[43]).toBe(0xe8)
    expect(rtcpPayload[47]).toBe(0xdd)
    expect(rtcpPayload[51]).toBe(0x44)
    expect(rtcpResult.drop).toBe(false)
  })

  it('redacts SDES CNAME and keeps packet length', () => {
    const cname = 'alice@192.168.1.10'
    const ssrc = 0x12345678
    const mapping = new SessionMapping()
    const mediaFlowIndex = new MediaFlowIndex()
    seedSipMedia(mapping, mediaFlowIndex, 5004)

    const sdes = buildSdes(ssrc, cname)
    const pkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5005, 40001, sdes)
    const result = sanitizePacket(
      { index: 1, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { mediaFlowIndex },
    )
    expect(result.drop).toBe(false)
    const out = apply(pkt, result)
    expect(out.length).toBe(pkt.length)
    expect(new TextDecoder('latin1').decode(out)).not.toContain(cname)
    expect(new TextDecoder('latin1').decode(out)).not.toContain('alice@')
  })

  it('masks unknown RTCP body but does not drop the packet', () => {
    const xr = new Uint8Array([0x80, 207, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78])
    const mapping = new SessionMapping()
    const mediaFlowIndex = new MediaFlowIndex()
    seedSipMedia(mapping, mediaFlowIndex, 5004)
    const pkt = buildEthIpUdp([192, 168, 1, 10], [10, 0, 0, 2], 5005, 40001, xr)
    const result = sanitizePacket(
      { index: 1, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
      { mediaFlowIndex },
    )
    expect(result.drop).toBe(false)
    const payload = apply(pkt, result).subarray(14 + 20 + 8)
    expect(payload[0]).toBe(0x80)
    expect(payload[1]).toBe(207)
    expect(payload[3]).toBe(0x01)
    expect(readU32(payload, 4)).not.toBe(0x12345678)
  })
})
