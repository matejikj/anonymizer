/**
 * Enterprise step 9 — PCAPNG allowlist (DSB/NRB drop) + IPv6 SRH / Home Address / NDP prefixes.
 */

import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import {
  DIAGNOSTIC_POLICY,
  sanitizePacket,
  PatchCollector,
  sanitizeIpv6Extensions,
} from '../../../src/pcap/sanitize'
import { readPcapng, writePcapng, scanPcapngForProhibitedBlocks, classifyPcapngBlock } from '../../../src/pcap/capture'
import { Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import { scanArtifactForOriginalLeaks } from '../../../src/pcap/trust'
import { sanitizeIcmpv6Ndp } from '../../../src/pcap/sanitize/tunnel'
import { ipv6TextToBytes16 } from '../../../src/pcap/sanitize/ipv6Wire'

function buildPcapngWithDsb(tlsKeyCanary: string): ArrayBuffer {
  const blocks: Uint8Array[] = []

  const shb = new ArrayBuffer(28)
  const shbV = new DataView(shb)
  shbV.setUint32(0, 0x0a0d0d0a, true)
  shbV.setUint32(4, 28, true)
  shbV.setUint32(8, 0x1a2b3c4d, true)
  shbV.setUint16(12, 1, true)
  shbV.setUint16(14, 0, true)
  shbV.setBigInt64(16, -1n, true)
  shbV.setUint32(24, 28, true)
  blocks.push(new Uint8Array(shb))

  const idb = new ArrayBuffer(20)
  const idbV = new DataView(idb)
  idbV.setUint32(0, 0x00000001, true)
  idbV.setUint32(4, 20, true)
  idbV.setUint16(8, 1, true)
  idbV.setUint32(12, 262144, true)
  idbV.setUint32(16, 20, true)
  blocks.push(new Uint8Array(idb))

  const canary = new TextEncoder().encode(tlsKeyCanary)
  const dsbPadded = (canary.length + 3) & ~3
  const dsbTotalLen = 12 + dsbPadded
  const dsb = new ArrayBuffer(dsbTotalLen)
  const dsbV = new DataView(dsb)
  dsbV.setUint32(0, 0x0000000a, true)
  dsbV.setUint32(4, dsbTotalLen, true)
  new Uint8Array(dsb, 8, canary.length).set(canary)
  dsbV.setUint32(dsbTotalLen - 4, dsbTotalLen, true)
  blocks.push(new Uint8Array(dsb))

  const nrbCanary = new TextEncoder().encode('NRB_HOSTNAME.secret.local')
  const nrbPad = (nrbCanary.length + 3) & ~3
  const nrbLen = 12 + nrbPad
  const nrb = new ArrayBuffer(nrbLen)
  const nrbV = new DataView(nrb)
  nrbV.setUint32(0, 0x00000004, true)
  nrbV.setUint32(4, nrbLen, true)
  new Uint8Array(nrb, 8, nrbCanary.length).set(nrbCanary)
  nrbV.setUint32(nrbLen - 4, nrbLen, true)
  blocks.push(new Uint8Array(nrb))

  const epbLen = 32 + 4
  const epb = new ArrayBuffer(epbLen)
  const epbV = new DataView(epb)
  epbV.setUint32(0, 0x00000006, true)
  epbV.setUint32(4, epbLen, true)
  epbV.setUint32(8, 0, true)
  epbV.setUint32(12, 0, true)
  epbV.setUint32(16, 0, true)
  epbV.setUint32(20, 4, true)
  epbV.setUint32(24, 4, true)
  new Uint8Array(epb, 28, 4).set([0xaa, 0xbb, 0xcc, 0xdd])
  epbV.setUint32(epbLen - 4, epbLen, true)
  blocks.push(new Uint8Array(epb))

  let total = 0
  for (const b of blocks) total += b.length
  const result = new Uint8Array(total)
  let off = 0
  for (const b of blocks) {
    result.set(b, off)
    off += b.length
  }
  return result.buffer
}

function buildEthIpv6(
  src: Uint8Array,
  dst: Uint8Array,
  nextHeader: number,
  extensionsAndPayload: Uint8Array,
): Uint8Array {
  const total = 14 + 40 + extensionsAndPayload.length
  const buf = new Uint8Array(total)
  buf.set([0x33, 0x33, 0x00, 0x00, 0x00, 0x01], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x86
  buf[13] = 0xdd
  buf[14] = 0x60
  buf[18] = (extensionsAndPayload.length >> 8) & 0xff
  buf[19] = extensionsAndPayload.length & 0xff
  buf[20] = nextHeader
  buf[21] = 64
  buf.set(src, 22)
  buf.set(dst, 38)
  buf.set(extensionsAndPayload, 54)
  return buf
}

describe('enterprise step 9 — PCAPNG allowlist / DSB', () => {
  it('classifies DSB/NRB as drop-prohibited', () => {
    expect(classifyPcapngBlock(0x0000000a)).toBe('drop-prohibited')
    expect(classifyPcapngBlock(0x00000004)).toBe('drop-prohibited')
    expect(classifyPcapngBlock(0x00000006)).toBe('keep')
    expect(classifyPcapngBlock(0x00000bad)).toBe('drop-unknown')
  })

  it('drops DSB on ingest; export has no secrets block; leak scanner negative for TLS key', () => {
    const tlsKey = 'CLIENT_RANDOM deadbeef TLS_MASTER_SECRET_KEY_9f3a'
    const input = buildPcapngWithDsb(tlsKey)
    const parsed = readPcapng(input)
    expect(parsed.droppedDsbBlocks).toBe(1)
    expect(parsed.droppedNrbBlocks).toBe(1)
    expect(parsed.droppedMetadataBlocks).toBeGreaterThanOrEqual(2)

    const written = writePcapng({
      sections: parsed.sections,
      interfaces: parsed.interfaces,
      packets: parsed.packets,
    })
    const out = new Uint8Array(written)
    const text = new TextDecoder().decode(out)
    expect(text).not.toContain(tlsKey)
    expect(text).not.toContain('NRB_HOSTNAME.secret.local')

    const prohibited = scanPcapngForProhibitedBlocks(out)
    expect(prohibited.dsb).toBe(0)
    expect(prohibited.nrb).toBe(0)
    expect(prohibited.isb).toBe(0)

    const leak = scanArtifactForOriginalLeaks({
      artifact: out,
      originals: [
        { category: 'secret', value: tlsKey, packetNumber: 0 },
        { category: 'hostname', value: 'NRB_HOSTNAME.secret.local', packetNumber: 0 },
      ],
    })
    expect(leak.findings.length).toBe(0)
    expect(leak.leakHits).toBe(0)
  })
})

describe('enterprise step 9 — IPv6 SRH / Home Address / NDP prefix', () => {
  it('maps SRH Type 4 segment list addresses', () => {
    const seg0 = ipv6TextToBytes16('2001:db8::1')
    const seg1 = ipv6TextToBytes16('2001:db8::2')
    // Hdr Ext Len = 4 → (4+1)*8 = 40 bytes (8 fixed + 2*16)
    const srh = new Uint8Array(40)
    srh[0] = 59 // next = No Next Header
    srh[1] = 4
    srh[2] = 4 // Routing Type = SRH
    srh[3] = 1 // Segments Left
    srh[4] = 1 // Last Entry
    srh.set(seg0, 8)
    srh.set(seg1, 24)

    const src = ipv6TextToBytes16('fe80::1')
    const dst = ipv6TextToBytes16('fe80::2')
    const pkt = buildEthIpv6(src, dst, 43, srh)
    const mapping = new SessionMapping()
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    expect(result.coverage.some((c) => c.protocol === 'ipv6-srh')).toBe(true)
    const out = pkt.slice()
    for (const p of result.patches) out.set(p.data, p.offset)
    expect([...out.subarray(54 + 8, 54 + 24)]).not.toEqual([...seg0])
    expect([...out.subarray(54 + 24, 54 + 40)]).not.toEqual([...seg1])
  })

  it('maps Destination Options Home Address (type 201)', () => {
    const home = ipv6TextToBytes16('2001:db8:cafe::9')
    // Dest opts: NH=59, HdrExtLen=2 → 24 bytes; PadN + Home Address
    // Home Address option: type 201, len 16, 16-byte addr → 18 bytes + need pad to 24-2=22...
    // Structure: [NH][len=2][opt...] total 24
    // Use: Pad1 + Home Address (1+18=19) + PadN(len=2 → 4 bytes) = 23... let's set HdrExtLen=3 → 32 bytes
    const dstOpt = new Uint8Array(32)
    dstOpt[0] = 59
    dstOpt[1] = 3 // (3+1)*8 = 32
    dstOpt[2] = 201 // Home Address
    dstOpt[3] = 16
    dstOpt.set(home, 4)
    // rest pad zeros

    const src = ipv6TextToBytes16('fe80::10')
    const dst = ipv6TextToBytes16('fe80::20')
    const pkt = buildEthIpv6(src, dst, 60, dstOpt)
    const mapping = new SessionMapping()
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    expect(result.coverage.some((c) => c.protocol === 'ipv6-home-address')).toBe(true)
    const out = pkt.slice()
    for (const p of result.patches) out.set(p.data, p.offset)
    expect([...out.subarray(54 + 4, 54 + 20)]).not.toEqual([...home])
  })

  it('maps NDP Prefix Information and target link-local on NS', () => {
    const target = ipv6TextToBytes16('fe80::abcd')
    // NS: type 135, code 0, checksum 0, reserved 4, target 16 = 24 fixed
    // + Prefix Information option type 3 len 4 (32 bytes): prefix at +16
    const prefix = ipv6TextToBytes16('2001:db8:1::')
    const icmp = new Uint8Array(24 + 32)
    icmp[0] = 135
    icmp.set(target, 8)
    icmp[24] = 3 // Prefix Information
    icmp[25] = 4 // 32 bytes
    icmp[26] = 64 // prefix length
    icmp.set(prefix, 24 + 16)

    const mapping = new SessionMapping()
    const collector = new PatchCollector(icmp.length)
    const coverage = sanitizeIcmpv6Ndp(icmp, 0, icmp.length, 135, collector, mapping)
    expect(coverage).not.toBeNull()
    expect(coverage!.some((c) => c.protocol === 'ndp-prefix')).toBe(true)
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
    const out = icmp.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)
    expect([...out.subarray(8, 24)]).not.toEqual([...target])
    expect([...out.subarray(24 + 16, 24 + 32)]).not.toEqual([...prefix])
  })

  it('sanitizeIpv6Extensions returns fragment flag', () => {
    const frag = new Uint8Array(8)
    frag[0] = 59
    frag[2] = 0x00
    frag[3] = 0x08 // fragment offset > 0
    const mapping = new SessionMapping()
    const collector = new PatchCollector(frag.length)
    const result = sanitizeIpv6Extensions({
      buffer: frag,
      startOffset: 0,
      initialNextHeader: 44,
      collector,
      mapping,
      packetIndex: 0,
    })
    expect(result.isFragment).toBe(true)
  })
})
