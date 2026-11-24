import { describe, it, expect } from 'vitest'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { readPcapng } from '../../../src/pcap/capture/pcapngReader'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { writePcapng } from '../../../src/pcap/capture/pcapngWriter'
import { validateClassicPcap, validatePcapng } from '../../../src/pcap/capture/validator'
import { sanitizePacket, HIGH_PRIVACY_POLICY, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { decodeLink } from '../../../src/pcap/protocols/registry'
import { initProtocols } from '../../../src/pcap/protocols/init'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { ClassicPcapHeader, PacketEnvelope } from '../../../src/pcap/domain/types'
import { readdirSync, readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Coverage-oriented fuzz + minimized regression fixtures (ARCHITECTURE §30 / Krok 9).
 * Never crashes, never allocates from attacker-controlled lengths.
 */

function randomBytes(len: number, seed = 1): ArrayBuffer {
  const buf = new ArrayBuffer(len)
  const arr = new Uint8Array(buf)
  let s = seed >>> 0
  for (let i = 0; i < len; i++) {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0
    arr[i] = s & 0xff
  }
  return buf
}

function mutateBuffer(src: ArrayBuffer, mutations: number, seed: number): ArrayBuffer {
  const out = src.slice(0)
  const arr = new Uint8Array(out)
  let s = seed >>> 0
  for (let m = 0; m < mutations; m++) {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0
    if (arr.length === 0) break
    const idx = s % arr.length
    arr[idx] = (arr[idx]! ^ ((s >> 8) & 0xff)) & 0xff
  }
  return out
}

const FIXTURE_DIR = join(import.meta.dirname, '../fixtures/fuzz-corpus')

describe('Fuzz corpus: minimized regression fixtures never crash', () => {
  it('loads every fixture under fuzz-corpus/', () => {
    if (!existsSync(FIXTURE_DIR)) return
    // Corpus is regenerated on demand via `npm run pcap:fuzz-corpus` (wired into
    // `npm run pcap:hardening`) — an empty directory here is a valid state, not a failure.
    const files = readdirSync(FIXTURE_DIR).filter((f) => f.endsWith('.bin') || f.endsWith('.pcap') || f.endsWith('.pcapng'))
    for (const file of files) {
      const raw = readFileSync(join(FIXTURE_DIR, file))
      const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength)
      expect(() => {
        readClassicPcap(buf)
        readPcapng(buf)
        validateClassicPcap(buf)
        validatePcapng(buf)
      }).not.toThrow()
    }
  })
})

describe('Fuzz: decoder + sanitizer never crash on random frames', () => {
  it('random ethernet-looking frames', () => {
    initProtocols()
    for (let i = 0; i < 80; i++) {
      const data = new Uint8Array(randomBytes(14 + (i % 200), 1000 + i))
      expect(() => decodeLink(data, 1)).not.toThrow()
      const mapping = new SessionMapping()
      expect(() =>
        sanitizePacket(
          { index: 0, data, capturedLength: data.length, originalLength: data.length, linkType: 1 },
          i % 2 === 0 ? HIGH_PRIVACY_POLICY : DIAGNOSTIC_POLICY,
          mapping,
        ),
      ).not.toThrow()
    }
  })

  it('mutated valid packets stay bounded', () => {
    const valid = new Uint8Array(42)
    valid.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    valid.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
    valid[12] = 0x08
    valid[13] = 0x00
    valid[14] = 0x45
    valid[16] = 0
    valid[17] = 28
    valid[23] = 17
    valid.set([192, 168, 1, 1], 26)
    valid.set([10, 0, 0, 1], 30)

    for (let i = 0; i < 60; i++) {
      const mutated = new Uint8Array(mutateBuffer(valid.buffer, 3 + (i % 5), 5000 + i))
      const t0 = performance.now()
      expect(() =>
        sanitizePacket(
          { index: 0, data: mutated, capturedLength: mutated.length, originalLength: mutated.length, linkType: 1 },
          HIGH_PRIVACY_POLICY,
          new SessionMapping(),
        ),
      ).not.toThrow()
      expect(performance.now() - t0).toBeLessThan(50)
    }
  })
})

describe('Fuzz: writer roundtrip under mutation', () => {
  it('classic writer accepts built envelopes without throwing', () => {
    const header: ClassicPcapHeader = {
      format: CaptureFormat.ClassicPcap,
      endian: Endian.Little,
      timestampResolution: TimestampResolution.Microseconds,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    }
    for (let i = 0; i < 20; i++) {
      const data = new Uint8Array(randomBytes(40 + (i % 40), 9000 + i))
      const pkt: PacketEnvelope = {
        packetNumber: 1,
        timestamp: { ticks: BigInt(i) * 1000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
        capturedLength: data.length,
        originalLength: data.length,
        linkType: 1,
        interfaceId: 0,
        sectionIndex: 0,
        fileOffset: 0,
        data,
      }
      expect(() => {
        const buf = writeClassicPcap({ header, packets: [pkt] })
        validateClassicPcap(buf)
        readClassicPcap(buf)
      }).not.toThrow()
    }
  })

  it('pcapng writer never throws on synthetic packets', () => {
    for (let i = 0; i < 15; i++) {
      const data = new Uint8Array(randomBytes(32 + (i % 64), 12000 + i))
      const pkt: PacketEnvelope = {
        packetNumber: 1,
        timestamp: { ticks: BigInt(i) * 1000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
        capturedLength: data.length,
        originalLength: data.length,
        linkType: 1,
        interfaceId: 0,
        sectionIndex: 0,
        fileOffset: 0,
        data,
      }
      expect(() => {
        const buf = writePcapng({
          sections: [{ sectionIndex: 0, endian: Endian.Little, versionMajor: 1, versionMinor: 0, sectionLength: -1n }],
          interfaces: [{
            interfaceId: 0,
            sectionIndex: 0,
            linkType: 1,
            snapLen: 65535,
            tsResol: TimestampResolution.Microseconds,
            tsResolValue: 6,
            tsOffset: 0n,
          }],
          packets: [pkt],
        })
        validatePcapng(buf)
        readPcapng(buf)
      }).not.toThrow()
    }
  })
})

describe('Fuzz: T16 binary toolkit walkers never throw', () => {
  it('random buffers through SoftCursor / TLV / BER / TBCD / UTF-16 / NTLM', async () => {
    const {
      SoftCursor,
      walkTlv,
      walkBer,
      decodeTbcd,
      encodeTbcd,
      looksLikeNtlmssp,
      parseNtlmssp,
      computeFixedLengthUtf16Bytes,
    } = await import('../../../src/pcap/protocols/application/binproto')
    for (let i = 0; i < 100; i++) {
      const data = new Uint8Array(randomBytes(8 + (i % 120), 42_000 + i))
      expect(() => {
        const cur = new SoftCursor(data)
        cur.u32(true)
        cur.u16(false)
        cur.slice(cur.remaining + 1)
        walkTlv(data, 0, data.length)
        walkBer(data, 0, data.length, { allowIndefinite: i % 2 === 0 })
        decodeTbcd(data.subarray(0, Math.min(8, data.length)))
        encodeTbcd('12345', 4)
        looksLikeNtlmssp(data)
        parseNtlmssp(data, 0, data.length)
        if (data.length >= 4 && data.length % 2 === 0) {
          try {
            computeFixedLengthUtf16Bytes(data.length & ~1, 'x', i % 2 === 0 ? 'le' : 'be')
          } catch {
            // length / surrogate errors are expected for adversarial input
          }
        }
      }).not.toThrow()
    }
  })
})

describe('Fuzz: IPv6 extension / nested length attacks', () => {
  it('deep IPv6 extension chain does not hang', () => {
    initProtocols()
    // Eth + IPv6 + many hop-by-hop style headers (next=0)
    const data = new Uint8Array(14 + 40 + 8 * 20)
    data[12] = 0x86
    data[13] = 0xdd
    data[14] = 0x60 // v6
    data[20] = 0 // next = hop-by-hop
    data[21] = 64
    let off = 54
    for (let i = 0; i < 19; i++) {
      data[off] = 0 // next hop-by-hop
      data[off + 1] = 0 // hdr ext len
      off += 8
    }
    data[off] = 17 // finally UDP
    const t0 = performance.now()
    expect(() => decodeLink(data, 1)).not.toThrow()
    expect(performance.now() - t0).toBeLessThan(100)
  })
})
