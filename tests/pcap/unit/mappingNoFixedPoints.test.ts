/**
 * @vitest-environment node
 *
 * Step 3 — mapping without fixed points: VLAN/IP/MAC/ephemeral port/radioId/SSRC
 * injectivity, stability, and VLAN 111 + PCP/DEI regression.
 */
import { describe, expect, it } from 'vitest'
import {
  SessionMapping,
  DEFAULT_MAPPING_CONFIG,
  allocateExclusiveId,
  allocateExclusiveIdSparse,
} from '../../../src/pcap/anonymization'
import { sanitizePacket } from '../../../src/pcap/sanitize/engine'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets'

function mulberry32(seed: number): () => number {
  let t = seed >>> 0
  return () => {
    t = (t + 0x6d2b79f5) >>> 0
    let r = Math.imul(t ^ (t >>> 15), 1 | t)
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r)
    return (r ^ (r >>> 14)) >>> 0
  }
}

describe('exclusive ID allocation (step 3)', () => {
  it('never returns a rejected or used id and fails closed when exhausted', () => {
    const used = new Set([1, 2, 3])
    const rnd = mulberry32(7)
    const got = allocateExclusiveId({
      used,
      min: 1,
      max: 4,
      reject: (n) => n === 4,
      nextRandom: rnd,
    })
    // Only free non-rejected slot would be none → null
    expect(got).toBeNull()
  })

  it('allocates a derangement over a small domain', () => {
    const used = new Set<number>()
    const rnd = mulberry32(42)
    const originals = [1, 2, 3, 4, 5]
    const aliases = originals.map((id) => {
      const alias = allocateExclusiveId({
        used,
        min: 1,
        max: 5,
        reject: (n) => n === id,
        nextRandom: rnd,
      })
      expect(alias).not.toBeNull()
      expect(alias).not.toBe(id)
      used.add(alias!)
      return alias!
    })
    expect(new Set(aliases).size).toBe(5)
  })

  it('short-circuits to null without scanning once the whole space is used (perf regression)', () => {
    // Real-45MB-capture regression: allocateExclusiveId's fallback does an O(space) linear
    // scan when the space is exhausted (e.g. the 16-bit IPv4-ID alias space on a real capture
    // with far more than 65,536 distinct IP-ID values to remap) — every subsequent call redid
    // that full scan only to fail identically, costing billions of iterations across a large
    // capture. Once `used` covers the whole [min, max] range, the result must still be null,
    // but nextRandom must never be consulted at all.
    const space = 100
    const used = new Set(Array.from({ length: space }, (_, i) => i))
    let calls = 0
    const alwaysCalledIfNotShortCircuited = () => {
      calls++
      return 0
    }
    const got = allocateExclusiveId({
      used,
      min: 0,
      max: space - 1,
      reject: () => false,
      nextRandom: alwaysCalledIfNotShortCircuited,
    })
    expect(got).toBeNull()
    expect(calls).toBe(0)
  })

  it('SSRC-sized sparse allocation rejects fixed points', () => {
    const used = new Set<number>()
    const rnd = mulberry32(99)
    for (let i = 0; i < 200; i++) {
      const original = (0x11110000 + i) >>> 0
      const alias = allocateExclusiveIdSparse({
        used,
        space: 0x100000000,
        reject: (n) => n === original,
        nextRandom: rnd,
      })
      expect(alias).not.toBeNull()
      expect(alias).not.toBe(original)
      used.add(alias!)
    }
    expect(used.size).toBe(200)
  })
})

describe('SessionMapping SSRC (step 6)', () => {
  it('never keeps a fixed point for SSRC aliases', () => {
    const m = new SessionMapping()
    for (const id of ['1', '305419896', '4294967295']) {
      const mapped = m.map('ssrc', id)
      expect(mapped).not.toBe(id)
      expect(mapped).toMatch(/^\d+$/)
    }
  })
})

describe('SessionMapping no fixed points (step 3)', () => {
  it('VLAN 111 maps to a different valid VLAN and is stable', () => {
    const m = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, vlan: 'map' })
    const a = m.map('vlan', '111')
    const b = m.map('vlan', '111')
    expect(a).toBe(b)
    expect(a).not.toBe('111')
    const id = Number.parseInt(a, 10)
    expect(id).toBeGreaterThanOrEqual(1)
    expect(id).toBeLessThanOrEqual(4094)
  })

  it('reserved VLAN 0 and 4095 stay reserved', () => {
    const m = new SessionMapping()
    expect(m.map('vlan', '0')).toBe('0')
    expect(m.map('vlan', '4095')).toBe('4095')
  })

  it('VLAN mapping is injective across many IDs', () => {
    const m = new SessionMapping()
    const seen = new Set<string>()
    for (let id = 1; id <= 500; id++) {
      const mapped = m.map('vlan', `${id}`)
      expect(mapped).not.toBe(`${id}`)
      expect(seen.has(mapped)).toBe(false)
      seen.add(mapped)
    }
  })

  it('VLAN exhaustion never echoes the original ID', () => {
    const m = new SessionMapping()
    // Fill all usable VLAN aliases except leave mapping of 2000 for last.
    for (let id = 1; id <= 4094; id++) {
      if (id === 2000) continue
      m.map('vlan', `${id}`)
    }
    const last = m.map('vlan', '2000')
    expect(last).not.toBe('2000')
    const lastId = Number.parseInt(last, 10)
    expect(lastId === 0 || (lastId >= 1 && lastId <= 4094)).toBe(true)
  })

  it('unicast IPv4 never keeps a fixed point and stays injective', () => {
    const m = new SessionMapping()
    const seen = new Set<string>()
    for (let i = 0; i < 300; i++) {
      const ip = `192.168.${(i >> 8) & 0xff}.${i & 0xff}`
      const mapped = m.map('ipv4', ip)
      expect(mapped).not.toBe(ip)
      expect(seen.has(mapped)).toBe(false)
      seen.add(mapped)
    }
  })

  it('unicast MAC never keeps a fixed point and stays injective', () => {
    const m = new SessionMapping()
    const seen = new Set<string>()
    for (let i = 0; i < 300; i++) {
      const mac = `aa:bb:cc:${((i >> 8) & 0xff).toString(16).padStart(2, '0')}:${(i & 0xff).toString(16).padStart(2, '0')}:01`
      const mapped = m.map('mac', mac)
      expect(mapped).not.toBe(mac)
      expect(seen.has(mapped)).toBe(false)
      seen.add(mapped)
    }
  })

  it('ephemeral port permute never keeps a fixed point', () => {
    const m = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' })
    const seen = new Set<string>()
    for (let port = 49152; port < 49152 + 1500; port++) {
      const canonical = `tcp/${port}`
      const mapped = m.map('port', canonical)
      expect(mapped).not.toBe(canonical)
      expect(seen.has(mapped)).toBe(false)
      seen.add(mapped)
    }
  })

  it('radioId never keeps a fixed point for non-reserved IDs', () => {
    const m = new SessionMapping()
    const seen = new Set<string>()
    for (let id = 1; id <= 400; id++) {
      const mapped = m.map('radioId', `${id}`)
      expect(mapped).not.toBe(`${id}`)
      expect(seen.has(mapped)).toBe(false)
      seen.add(mapped)
    }
  })
})

describe('VLAN 111 PCP/DEI regression (step 3)', () => {
  function buildEthVlanIpv4(vlanId: number, pcp: number, dei: number): Uint8Array {
    const tci = ((pcp & 0x7) << 13) | ((dei & 0x1) << 12) | (vlanId & 0xfff)
    const buf = new Uint8Array(14 + 4 + 20)
    buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01], 0)
    buf.set([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 6)
    buf[12] = 0x81
    buf[13] = 0x00
    buf[14] = (tci >> 8) & 0xff
    buf[15] = tci & 0xff
    buf[16] = 0x08
    buf[17] = 0x00
    // Minimal IPv4 header
    buf[18] = 0x45
    buf[20] = 0x00
    buf[21] = 20
    buf[27] = 1 // ICMP
    buf.set([10, 0, 0, 1], 30)
    buf.set([10, 0, 0, 2], 34)
    return buf
  }

  it('changes VLAN 111 and preserves PCP/DEI bits', () => {
    const pcp = 5
    const dei = 1
    const data = buildEthVlanIpv4(111, pcp, dei)
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, vlan: 'map' })
    const result = sanitizePacket(
      {
        index: 0,
        data,
        capturedLength: data.length,
        originalLength: data.length,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    expect(result.drop).toBe(false)

    const out = new Uint8Array(data)
    for (const p of result.patches) {
      out.set(p.data, p.offset)
    }

    const tci = (out[14]! << 8) | out[15]!
    const outPcp = (tci >> 13) & 0x7
    const outDei = (tci >> 12) & 0x1
    const outVid = tci & 0xfff
    expect(outPcp).toBe(pcp)
    expect(outDei).toBe(dei)
    expect(outVid).not.toBe(111)
    expect(outVid).toBeGreaterThanOrEqual(1)
    expect(outVid).toBeLessThanOrEqual(4094)
    expect(mapping.map('vlan', '111')).toBe(`${outVid}`)
  })

  it('reports reserved VLAN 0 explicitly without remapping', () => {
    const data = buildEthVlanIpv4(0, 0, 0)
    const mapping = new SessionMapping()
    const result = sanitizePacket(
      {
        index: 0,
        data,
        capturedLength: data.length,
        originalLength: data.length,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    expect(result.issues.some((i) => i === 'vlan-reserved-preserved:0')).toBe(true)
    const tciPatch = result.patches.find((p) => p.offset === 14)
    expect(tciPatch).toBeUndefined()
  })
})
