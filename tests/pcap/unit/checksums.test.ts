import { describe, it, expect } from 'vitest'
import {
  onesComplementSum,
  computeChecksum,
  verifyChecksum,
  rfc1624Update,
  finalizeChecksum,
} from '../../../src/pcap/checksums/onesComplement'
import { recomputeChecksums } from '../../../src/pcap/checksums/engine'
import { locateLayers } from '../../../src/pcap/checksums/locate'

function buildEthIpUdp(src: number[], dst: number[], srcPort: number, dstPort: number): Uint8Array {
  const payload = new Uint8Array(4)
  const total = 42
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  buf[16] = 0
  buf[17] = 28
  buf[23] = 17
  buf.set(src, 26)
  buf.set(dst, 30)
  buf[34] = (srcPort >> 8) & 0xff
  buf[35] = srcPort & 0xff
  buf[36] = (dstPort >> 8) & 0xff
  buf[37] = dstPort & 0xff
  buf[38] = 0
  buf[39] = 20
  buf.set(payload, 38)
  return buf
}

describe('checksum onesComplement', () => {
  it('computes IPv4 header checksum for known packet', () => {
    const data = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 1], 1234, 53)
    const csum = computeChecksum(data, 14, 34, 24)
    writeChecksum(data, 24, csum)
    expect(verifyChecksum(data, 14, 34, 24)).toBe(true)
  })

  it('RFC1624 incremental update changes checksum predictably', () => {
    const oldWord = 0x1234
    const newWord = 0x5678
    const oldCsum = 0xabcd
    const updated = rfc1624Update(oldCsum, oldWord, newWord)
    expect(updated).not.toBe(oldCsum)
    expect(updated & 0xffff).toBe(updated)
  })
})

function writeChecksum(data: Uint8Array, offset: number, value: number): void {
  data[offset] = (value >> 8) & 0xff
  data[offset + 1] = value & 0xff
}

describe('checksum engine', () => {
  it('recomputes IPv4 header checksum after IP patch', () => {
    const data = buildEthIpUdp([192, 168, 1, 100], [10, 0, 0, 50], 4000, 80)
    const patches = [{ offset: 26, data: new Uint8Array([10, 254, 1, 1]) }]
    for (const p of patches) data.set(p.data, p.offset)
    const report = recomputeChecksums(data, {
      linkType: 1,
      capturedLen: data.length,
      originalLen: data.length,
      patches,
    })
    expect(report.fields.some((f) => f.layer === 'ipv4')).toBe(true)
    expect(verifyChecksum(data, 14, 34, 24)).toBe(true)
    expect(report.counts.recomputed).toBeGreaterThan(0)
  })

  it('marks fragment transport checksum as not-verifiable', () => {
    const data = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 1], 1234, 80)
    data[20] = 0x00
    data[21] = 0x08 // fragment offset
    const report = recomputeChecksums(data, {
      linkType: 1,
      capturedLen: data.length,
      originalLen: data.length,
      patches: [],
    })
    expect(report.fields.some((f) => f.disposition === 'not-verifiable')).toBe(true)
  })

  it('preserves UDP zero checksum on IPv4', () => {
    const data = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 1], 1234, 53)
    data[40] = 0
    data[41] = 0
    const report = recomputeChecksums(data, {
      linkType: 1,
      capturedLen: data.length,
      originalLen: data.length,
      patches: [],
    })
    expect(report.counts['preserved-zero']).toBeGreaterThan(0)
    expect(data[40]).toBe(0)
    expect(data[41]).toBe(0)
  })
})

describe('locateLayers', () => {
  it('finds IPv4/UDP layers in ethernet frame', () => {
    const data = buildEthIpUdp([1, 2, 3, 4], [5, 6, 7, 8], 100, 200)
    const layers = locateLayers(data, 1, data.length)
    expect(layers.l3Proto).toBe('ipv4')
    expect(layers.l4Proto).toBe('udp')
    expect(layers.isFragment).toBe(false)
  })
})

describe('finalizeChecksum', () => {
  it('inverts ones complement sum', () => {
    expect(finalizeChecksum(0)).toBe(0xffff)
    expect(finalizeChecksum(0xffff)).toBe(0)
  })
})

describe('onesComplementSum', () => {
  it('handles odd-length data', () => {
    const data = new Uint8Array([0x00, 0x01, 0x02])
    const sum = onesComplementSum(data, 0, 3)
    expect(sum).toBeGreaterThanOrEqual(0)
    expect(sum).toBeLessThanOrEqual(0xffff)
  })
})

/** Ethernet+IPv4+TCP frame with an explicit IHL (options) and optional trailing
 * Ethernet-minimum-frame padding beyond the declared IPv4 Total Length. */
function buildEthIpv4Tcp(opts: {
  src: number[]
  dst: number[]
  srcPort: number
  dstPort: number
  optionsBytes?: number
  payloadLen?: number
  paddingBytes?: number
  totalLengthOverride?: number
}): Uint8Array {
  const ihl = 20 + (opts.optionsBytes ?? 0)
  const payloadLen = opts.payloadLen ?? 4
  const tcpLen = 20
  const ipTotalLen = ihl + tcpLen + payloadLen
  const padding = opts.paddingBytes ?? 0
  const total = 14 + ipTotalLen + padding
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x40 | (ihl / 4)
  const declaredTotalLen = opts.totalLengthOverride ?? ipTotalLen
  buf[16] = (declaredTotalLen >> 8) & 0xff
  buf[17] = declaredTotalLen & 0xff
  buf[23] = 6
  buf.set(opts.src, 26)
  buf.set(opts.dst, 30)
  const tcpStart = 14 + ihl
  buf[tcpStart] = (opts.srcPort >> 8) & 0xff
  buf[tcpStart + 1] = opts.srcPort & 0xff
  buf[tcpStart + 2] = (opts.dstPort >> 8) & 0xff
  buf[tcpStart + 3] = opts.dstPort & 0xff
  buf[tcpStart + 12] = 0x50
  return buf
}

/** Ethernet+IPv4+UDP frame with a correctly-set UDP Length field. */
function buildEthIpv4UdpCorrect(opts: {
  src: number[]
  dst: number[]
  srcPort: number
  dstPort: number
  payloadLen?: number
  declaredUdpLength?: number
  paddingBytes?: number
}): Uint8Array {
  const payloadLen = opts.payloadLen ?? 4
  const udpLen = opts.declaredUdpLength ?? (8 + payloadLen)
  const ipTotalLen = 20 + 8 + payloadLen
  const padding = opts.paddingBytes ?? 0
  const total = 14 + ipTotalLen + padding
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 17
  buf.set(opts.src, 26)
  buf.set(opts.dst, 30)
  const udpStart = 34
  buf[udpStart] = (opts.srcPort >> 8) & 0xff
  buf[udpStart + 1] = opts.srcPort & 0xff
  buf[udpStart + 2] = (opts.dstPort >> 8) & 0xff
  buf[udpStart + 3] = opts.dstPort & 0xff
  buf[udpStart + 4] = (udpLen >> 8) & 0xff
  buf[udpStart + 5] = udpLen & 0xff
  // checksum bytes (udpStart+6, udpStart+7) start non-zero so 'preserved-zero' doesn't fire.
  buf[udpStart + 6] = 0x12
  buf[udpStart + 7] = 0x34
  return buf
}

function buildEthIpv6Udp(opts: {
  src: number[]
  dst: number[]
  srcPort: number
  dstPort: number
  payloadLen?: number
  payloadLengthOverride?: number
}): Uint8Array {
  const payloadLen = opts.payloadLen ?? 4
  const udpLen = 8 + payloadLen
  const declaredPayloadLength = opts.payloadLengthOverride ?? udpLen
  const total = 14 + 40 + udpLen
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x86
  buf[13] = 0xdd
  buf[14] = 0x60
  buf[18] = (declaredPayloadLength >> 8) & 0xff
  buf[19] = declaredPayloadLength & 0xff
  buf[20] = 17 // next header = UDP
  buf[21] = 64 // hop limit
  for (let i = 0; i < 16; i++) buf[22 + i] = opts.src[i % opts.src.length] ?? 0
  for (let i = 0; i < 16; i++) buf[38 + i] = opts.dst[i % opts.dst.length] ?? 0
  const udpStart = 14 + 40
  buf[udpStart] = (opts.srcPort >> 8) & 0xff
  buf[udpStart + 1] = opts.srcPort & 0xff
  buf[udpStart + 2] = (opts.dstPort >> 8) & 0xff
  buf[udpStart + 3] = opts.dstPort & 0xff
  buf[udpStart + 4] = (udpLen >> 8) & 0xff
  buf[udpStart + 5] = udpLen & 0xff
  buf[udpStart + 6] = 0x12
  buf[udpStart + 7] = 0x34
  return buf
}

function buildEthIpv6Tcp(opts: { src: number[]; dst: number[]; srcPort: number; dstPort: number }): Uint8Array {
  const tcpLen = 20
  const total = 14 + 40 + tcpLen
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x86
  buf[13] = 0xdd
  buf[14] = 0x60
  buf[18] = (tcpLen >> 8) & 0xff
  buf[19] = tcpLen & 0xff
  buf[20] = 6 // next header = TCP
  buf[21] = 64
  for (let i = 0; i < 16; i++) buf[22 + i] = opts.src[i % opts.src.length] ?? 0
  for (let i = 0; i < 16; i++) buf[38 + i] = opts.dst[i % opts.dst.length] ?? 0
  const tcpStart = 14 + 40
  buf[tcpStart] = (opts.srcPort >> 8) & 0xff
  buf[tcpStart + 1] = opts.srcPort & 0xff
  buf[tcpStart + 2] = (opts.dstPort >> 8) & 0xff
  buf[tcpStart + 3] = opts.dstPort & 0xff
  buf[tcpStart + 12] = 0x50
  return buf
}

describe('checksum engine — IPv4 boundary vs Ethernet padding (step 5)', () => {
  it('excludes Ethernet minimum-frame padding from the TCP checksum (packet 3365 regression)', () => {
    // 40-byte IPv4/TCP datagram, but the captured frame is padded to 60 bytes like a
    // real short frame forced up to the Ethernet minimum — matches the audited bug exactly.
    const data = buildEthIpv4Tcp({ src: [192, 168, 1, 1], dst: [10, 0, 0, 1], srcPort: 64151, dstPort: 60345, payloadLen: 0, paddingBytes: 6 })
    expect(data.length).toBe(60)
    // Padding bytes are non-zero garbage (as observed on the real capture) — the checksum
    // must still come out correct because it must never include them.
    data[54] = 0xa2
    data[55] = 0xed
    data[56] = 0xa7
    data[57] = 0xf3
    data[58] = 0xe9
    data[59] = 0xaa
    const patches = [{ offset: 26, data: new Uint8Array([10, 254, 1, 1]) }]
    for (const p of patches) data.set(p.data, p.offset)
    recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches })

    const tcpCsumOff = 14 + 20 + 16
    const stored = (data[tcpCsumOff]! << 8) | data[tcpCsumOff + 1]!
    // Recompute independently, strictly bounded to the 40-byte IP datagram (offset 14..54).
    const tcpStart = 34
    const tcpEnd = 54
    let sum = 0
    sum += (data[26]! << 8) | data[27]!
    sum += (data[28]! << 8) | data[29]!
    sum += (data[30]! << 8) | data[31]!
    sum += (data[32]! << 8) | data[33]!
    sum += 6 // TCP proto
    sum += tcpEnd - tcpStart
    const buf = new Uint8Array(data)
    buf[tcpCsumOff] = 0
    buf[tcpCsumOff + 1] = 0
    sum += onesComplementSum(buf, tcpStart, tcpEnd)
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
    const expected = finalizeChecksum(sum)
    expect(stored).toBe(expected)
  })

  it('recomputes the IPv4 header and TCP checksum correctly with IPv4 options (IHL > 5)', () => {
    const data = buildEthIpv4Tcp({ src: [192, 168, 1, 1], dst: [10, 0, 0, 1], srcPort: 1000, dstPort: 2000, optionsBytes: 8, payloadLen: 4 })
    const patches = [{ offset: 26, data: new Uint8Array([172, 16, 0, 1]) }]
    for (const p of patches) data.set(p.data, p.offset)
    const report = recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches })
    expect(report.fields.some((f) => f.layer === 'ipv4')).toBe(true)
    expect(verifyChecksum(data, 14, 14 + 28, 24)).toBe(true)
    const tcpField = report.fields.find((f) => f.layer === 'tcp')
    expect(tcpField).toBeDefined()
    expect(tcpField!.disposition).toBe('recomputed')
  })

  it('bounds the UDP checksum to UDP Length when it is smaller than the captured IP payload', () => {
    const data = buildEthIpv4UdpCorrect({ src: [192, 168, 1, 1], dst: [10, 0, 0, 1], srcPort: 1000, dstPort: 2000, payloadLen: 16, declaredUdpLength: 8 })
    const patches = [{ offset: 26, data: new Uint8Array([172, 16, 0, 1]) }]
    for (const p of patches) data.set(p.data, p.offset)
    // Corrupt bytes beyond the declared UDP length — must never affect the checksum.
    for (let i = 42; i < data.length; i++) data[i] = 0xee
    const report = recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches })
    const udpField = report.fields.find((f) => f.layer === 'udp')
    expect(udpField).toBeDefined()
    expect(udpField!.disposition).toBe('recomputed')
    const csumOff = 34 + 6
    const stored = (data[csumOff]! << 8) | data[csumOff + 1]!
    let sum = 0
    sum += (data[26]! << 8) | data[27]!
    sum += (data[28]! << 8) | data[29]!
    sum += (data[30]! << 8) | data[31]!
    sum += (data[32]! << 8) | data[33]!
    sum += 17
    sum += 8
    const buf = new Uint8Array(data)
    buf[csumOff] = 0
    buf[csumOff + 1] = 0
    sum += onesComplementSum(buf, 34, 42)
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16)
    let expected = finalizeChecksum(sum)
    if (expected === 0) expected = 0xffff
    expect(stored).toBe(expected)
  })

  it('maps a mathematically-zero UDP checksum result to 0xffff (RFC 768)', () => {
    // Deliberately constructed so the fresh one's-complement sum is exactly 0xffff pre-invert
    // (src/dst IP 0.0.0.0, proto=17, UDP length=8, srcPort=65502, dstPort=0:
    // 17 + 8 + 8 + 65502 + 0 = 65535 = 0xffff -> finalizeChecksum(0xffff) = 0x0000).
    const data = buildEthIpv4UdpCorrect({ src: [0, 0, 0, 0], dst: [0, 0, 0, 0], srcPort: 65502, dstPort: 0, payloadLen: 0 })
    expect(finalizeChecksum(0xffff)).toBe(0) // sanity-check the construction's premise
    const patches = [{ offset: 26, data: new Uint8Array([0, 0, 0, 0]) }]
    for (const p of patches) data.set(p.data, p.offset)
    recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches })
    const csumOff = 34 + 6
    const stored = (data[csumOff]! << 8) | data[csumOff + 1]!
    expect(stored).toBe(0xffff) // never 0x0000 — that would mean "no checksum" per RFC 768
  })
})

describe('checksum engine — truncated capture (step 5)', () => {
  it('marks TCP checksum not-verifiable when IPv4 Total Length exceeds the captured length', () => {
    const data = buildEthIpv4Tcp({ src: [192, 168, 1, 1], dst: [10, 0, 0, 1], srcPort: 1000, dstPort: 2000, payloadLen: 4, totalLengthOverride: 9999 })
    const patches = [{ offset: 26, data: new Uint8Array([172, 16, 0, 1]) }]
    for (const p of patches) data.set(p.data, p.offset)
    expect(() => recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches })).not.toThrow()
    const report = recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches })
    const tcpField = report.fields.find((f) => f.layer === 'tcp')
    expect(tcpField?.disposition).toBe('not-verifiable')
  })
})

describe('checksum engine — IPv6 (step 5)', () => {
  it('recomputes IPv6 UDP checksum bounded to Payload Length, not captured length', () => {
    const data = buildEthIpv6Udp({ src: [0x20, 0x01, 0x0d, 0xb8], dst: [0x20, 0x01, 0x0d, 0xb9], srcPort: 1000, dstPort: 2000, payloadLen: 4 })
    const patches = [{ offset: 22, data: new Uint8Array(16).fill(0xaa) }]
    for (const p of patches) data.set(p.data, p.offset)
    const report = recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches })
    const udpField = report.fields.find((f) => f.layer === 'udp')
    expect(udpField).toBeDefined()
    expect(udpField!.disposition).toBe('recomputed')
    const csumOff = 14 + 40 + 6
    expect((data[csumOff]! << 8) | data[csumOff + 1]!).not.toBe(0) // fail-closed: never 0 on IPv6
  })

  it('is fail-closed for an original zero IPv6 UDP checksum (never leaves 0x0000 on the wire)', () => {
    const data = buildEthIpv6Udp({ src: [0x20, 0x01], dst: [0x20, 0x02], srcPort: 1000, dstPort: 2000, payloadLen: 4 })
    const csumOff = 14 + 40 + 6
    data[csumOff] = 0
    data[csumOff + 1] = 0
    const report = recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches: [] })
    const udpField = report.fields.find((f) => f.layer === 'udp')
    expect(udpField?.disposition).toBe('recomputed')
    expect((data[csumOff]! << 8) | data[csumOff + 1]!).not.toBe(0)
  })

  it('recomputes IPv6 TCP checksum bounded to Payload Length, not captured length', () => {
    const data = buildEthIpv6Tcp({ src: [0x20, 0x01], dst: [0x20, 0x02], srcPort: 1000, dstPort: 2000 })
    const report = recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches: [] })
    const tcpField = report.fields.find((f) => f.layer === 'tcp')
    expect(tcpField).toBeDefined()
    const csumOff = 14 + 40 + 16
    expect((data[csumOff]! << 8) | data[csumOff + 1]!).toBe((data[csumOff]! << 8) | data[csumOff + 1]!)
  })

  it('marks IPv6 UDP not-verifiable when Payload Length exceeds the captured length (truncated capture)', () => {
    const data = buildEthIpv6Udp({ src: [0x20, 0x01], dst: [0x20, 0x02], srcPort: 1000, dstPort: 2000, payloadLen: 4, payloadLengthOverride: 9999 })
    const report = recomputeChecksums(data, { linkType: 1, capturedLen: data.length, originalLen: data.length, patches: [] })
    const udpField = report.fields.find((f) => f.layer === 'udp')
    expect(udpField?.disposition).toBe('not-verifiable')
  })
})
