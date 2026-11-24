/**
 * Step 7 — query extractor + index search (exact / ambiguous / packet context).
 * Search path must not touch network APIs or DATA frames.
 */

import { describe, expect, it, vi } from 'vitest'
import { bytesToHex } from '../../src/crypto/incrementalSha256'
import { PCAP_RECOVERY_ERROR } from '../../src/pcap/recovery/domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../../src/pcap/recovery/domain/limits'
import {
  serializeRecoveryIndexSeed,
  type RecoveryIndexSeedEntryInput,
} from '../../src/pcap/recovery/export/recoveryIndexSeedPort'
import { buildCompactIndexFromSeed } from '../../src/pcap/recovery/export/compactIndexBuilder'
import { extractRecoveryQuery } from '../../src/pcap/recovery/restore/queryExtractor'
import { searchUnlockedIndex } from '../../src/pcap/recovery/restore/recoverySearch'
import { buildUnlockedLookupIndex } from '../../src/pcap/recovery/restore/unlockedLookupIndex'
import type { UnlockedLookupIndex } from '../../src/pcap/recovery/restore/unlockedLookupIndex'

function makeSourceBuffer(): ArrayBuffer {
  const ipv4A = new Uint8Array([10, 1, 2, 3])
  const ipv4B = new Uint8Array([10, 9, 8, 7])
  const mac = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
  const host = new TextEncoder().encode('sip.example.test')
  const packetData = new Uint8Array(96)
  packetData.set(ipv4A, 0)
  packetData.set(mac, 8)
  packetData.set(host, 20)
  packetData.set(ipv4B, 48)

  const size = 24 + 16 + packetData.length + 16 + packetData.length
  const buf = new ArrayBuffer(size)
  const view = new DataView(buf)
  view.setUint32(0, 0xa1b2c3d4, true)
  view.setUint16(4, 2, true)
  view.setUint16(6, 4, true)
  view.setUint32(16, 65535, true)
  view.setUint32(20, 1, true)

  // packet 1
  view.setUint32(24 + 8, packetData.length, true)
  view.setUint32(24 + 12, packetData.length, true)
  new Uint8Array(buf, 40, packetData.length).set(packetData)

  // packet 2
  const off2 = 40 + packetData.length
  view.setUint32(off2 + 8, packetData.length, true)
  view.setUint32(off2 + 12, packetData.length, true)
  new Uint8Array(buf, off2 + 16, packetData.length).set(packetData)

  return buf
}

async function buildIndex(entries: RecoveryIndexSeedEntryInput[]): Promise<UnlockedLookupIndex> {
  const buffer = makeSourceBuffer()
  const seed = serializeRecoveryIndexSeed({
    generationId: 'gen-step7',
    mappingRevision: 1,
    originalPacketCount: 2,
    anonymizedPacketCount: 2,
    droppedPacketIndexes: [],
    entries,
  })
  expect(seed.ok).toBe(true)
  if (!seed.ok) throw new Error('seed')
  const built = await buildCompactIndexFromSeed({
    indexSeed: seed.value,
    sourceBlob: new Blob([buffer]),
    rangeDirectory: [],
  })
  expect(built.ok).toBe(true)
  if (!built.ok) throw new Error('index')
  const unlocked = buildUnlockedLookupIndex(built.value.plaintext)
  expect(unlocked.ok).toBe(true)
  if (!unlocked.ok) throw new Error('unlock index')
  return unlocked.value
}

describe('Step 7 — queryExtractor', () => {
  it('extracts IP, MAC, hostname, URI, SIP, port/VLAN and packet refs', () => {
    const text = [
      'Suspect: 10.0.0.1 and aa:bb:cc:dd:ee:ff',
      'Host sip.example.test URI https://diag.example/path',
      'Call-ID: abc123@sip.example.test branch=z9hG4bKdeadbeef',
      'port 5060 vlan 100',
      'See packet 317 and paket 12 frame 99',
    ].join('\n')

    const r = extractRecoveryQuery(text)
    expect(r.ok).toBe(true)
    if (!r.ok) return

    const kinds = r.value.candidates.map((c) =>
      c.kind === 'packet' ? `p:${c.anonymizedPacketNumber}` : `v:${c.categoryHint}:${c.text}`,
    )
    expect(kinds.some((k) => k.startsWith('v:ipv4:10.0.0.1'))).toBe(true)
    expect(kinds.some((k) => k.toLowerCase().includes('aa:bb:cc:dd:ee:ff'))).toBe(true)
    expect(kinds.some((k) => k.includes('hostname') && k.includes('sip.example.test'))).toBe(true)
    expect(kinds.some((k) => k.includes('url') && k.includes('https://diag.example/path'))).toBe(true)
    expect(kinds.some((k) => k.includes('sip-call-id') || k.includes('sip-token'))).toBe(true)
    expect(kinds.some((k) => k.includes('port:5060'))).toBe(true)
    expect(kinds.some((k) => k.includes('vlan:100'))).toBe(true)
    expect(kinds).toContain('p:317')
    expect(kinds).toContain('p:12')
    expect(kinds).toContain('p:99')
  })

  it('rejects oversize queries', () => {
    const huge = 'x'.repeat(PCAP_RECOVERY_LIMITS.maxQueryBytes + 1)
    const r = extractRecoveryQuery(huge)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.code).toBe(PCAP_RECOVERY_ERROR.queryInvalid)
  })

  it('caps candidates at maxQueryCandidates', () => {
    const ips = Array.from({ length: 300 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`).join(' ')
    const r = extractRecoveryQuery(ips)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.value.candidates.length).toBeLessThanOrEqual(PCAP_RECOVERY_LIMITS.maxQueryCandidates)
    expect(r.value.truncated).toBe(true)
  })
})

describe('Step 7 — searchUnlockedIndex', () => {
  it('resolves exact anonymized values and withholds ambiguous originals', async () => {
    const index = await buildIndex([
      {
        category: 'ipv4',
        matchKind: 'exact',
        anonymizedCanonical: '10.0.0.1',
        anonymizedWire: '10.0.0.1',
        occurrences: [
          {
            originalPacketNumber: 1,
            anonymizedPacketNumber: 1,
            fileOffset: 24,
            dataOffset: 40,
            byteOffsetInPacket: 0,
            byteLength: 4,
            protocolId: 1,
            fieldId: 1,
          },
        ],
      },
      {
        category: 'ipv4',
        matchKind: 'exact',
        anonymizedCanonical: '198.51.100.9',
        anonymizedWire: '198.51.100.9',
        occurrences: [
          {
            originalPacketNumber: 1,
            anonymizedPacketNumber: 1,
            fileOffset: 24,
            dataOffset: 40,
            byteOffsetInPacket: 0,
            byteLength: 4,
            protocolId: 1,
            fieldId: 2,
          },
        ],
      },
      {
        category: 'ipv4',
        matchKind: 'exact',
        anonymizedCanonical: '198.51.100.9',
        anonymizedWire: '198.51.100.9',
        occurrences: [
          {
            originalPacketNumber: 2,
            anonymizedPacketNumber: 2,
            fileOffset: 40 + 96,
            dataOffset: 40 + 96 + 16,
            byteOffsetInPacket: 48,
            byteLength: 4,
            protocolId: 1,
            fieldId: 3,
          },
        ],
      },
    ])

    const exact = searchUnlockedIndex({ index, query: 'Found 10.0.0.1 in capture' })
    expect(exact.ok).toBe(true)
    if (!exact.ok) return
    const exactHit = exact.value.hits.find((h) => h.queriedValue === '10.0.0.1')
    expect(exactHit?.status).toBe('exact')
    expect(exactHit?.originalValue).toBe(bytesToHex(new Uint8Array([10, 1, 2, 3])))

    const amb = searchUnlockedIndex({ index, query: 'shared mask 198.51.100.9' })
    expect(amb.ok).toBe(true)
    if (!amb.ok) return
    const ambHit = amb.value.hits.find((h) => h.queriedValue === '198.51.100.9')
    expect(ambHit?.status).toBe('ambiguous')
    expect(ambHit?.originalValue).toBeUndefined()
    expect(ambHit?.candidateCount).toBeGreaterThan(1)

    index.wipe()
  })

  it('narrows with packet context and supports packet-number lookup', async () => {
    const index = await buildIndex([
      {
        category: 'ipv4',
        matchKind: 'exact',
        anonymizedCanonical: '10.0.0.1',
        anonymizedWire: '10.0.0.1',
        occurrences: [
          {
            originalPacketNumber: 1,
            anonymizedPacketNumber: 1,
            fileOffset: 24,
            dataOffset: 40,
            byteOffsetInPacket: 0,
            byteLength: 4,
            protocolId: 1,
            fieldId: 1,
          },
        ],
      },
      {
        category: 'ipv4',
        matchKind: 'exact',
        anonymizedCanonical: '10.0.0.1',
        anonymizedWire: '10.0.0.1',
        occurrences: [
          {
            originalPacketNumber: 2,
            anonymizedPacketNumber: 2,
            fileOffset: 40 + 96,
            dataOffset: 40 + 96 + 16,
            byteOffsetInPacket: 0,
            byteLength: 4,
            protocolId: 1,
            fieldId: 1,
          },
        ],
      },
      {
        category: 'hostname',
        matchKind: 'exact',
        anonymizedCanonical: 'anon.host',
        anonymizedWire: 'anon.host',
        occurrences: [
          {
            originalPacketNumber: 1,
            anonymizedPacketNumber: 1,
            fileOffset: 24,
            dataOffset: 40,
            byteOffsetInPacket: 20,
            byteLength: 'sip.example.test'.length,
            protocolId: 2,
            fieldId: 3,
          },
        ],
      },
    ])

    // Without context: two entries for same mask → ambiguous, no original.
    const open = searchUnlockedIndex({ index, query: '10.0.0.1' })
    expect(open.ok).toBe(true)
    if (!open.ok) return
    const openHit = open.value.hits.find((h) => h.queriedValue === '10.0.0.1')
    expect(openHit?.status).toBe('ambiguous')
    expect(openHit?.originalValue).toBeUndefined()

    // With packet context: narrow to one entry and reveal.
    const combo = searchUnlockedIndex({
      index,
      query: 'AI says 10.0.0.1 appeared in packet 2',
    })
    expect(combo.ok).toBe(true)
    if (!combo.ok) return
    const comboHit = combo.value.hits.find((h) => h.queriedValue === '10.0.0.1')
    expect(comboHit?.status).toBe('exact')
    expect(comboHit?.originalValue).toBeDefined()

    const pkt = searchUnlockedIndex({ index, query: 'paket 1' })
    expect(pkt.ok).toBe(true)
    if (!pkt.ok) return
    expect(pkt.value.hits.some((h) => h.anonymizedPacketNumber === 1)).toBe(true)

    for (let i = 0; i < 10; i++) {
      const again = searchUnlockedIndex({ index, query: '10.0.0.1' })
      expect(again.ok).toBe(true)
      if (!again.ok) return
      expect(again.value.hits.some((h) => h.status === 'exact' || h.status === 'ambiguous')).toBe(true)
    }

    index.wipe()
  })

  it('paginates results and never calls network APIs', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('network forbidden')
    })
    const wsSpy = vi.spyOn(globalThis, 'WebSocket').mockImplementation(() => {
      throw new Error('network forbidden')
    })

    const entries: RecoveryIndexSeedEntryInput[] = Array.from({ length: 8 }, (_, i) => ({
      category: 'ipv4' as const,
      matchKind: 'exact' as const,
      anonymizedCanonical: `198.51.100.${i + 1}`,
      anonymizedWire: `198.51.100.${i + 1}`,
      occurrences: [
        {
          originalPacketNumber: 1,
          anonymizedPacketNumber: 1,
          fileOffset: 24,
          dataOffset: 40,
          byteOffsetInPacket: 0,
          byteLength: 4,
          protocolId: 1,
          fieldId: i + 1,
        },
      ],
    }))
    const index = await buildIndex(entries)
    const query = entries.map((e) => e.anonymizedCanonical).join(' ')
    const page1 = searchUnlockedIndex({ index, query, offset: 0, limit: 3 })
    expect(page1.ok).toBe(true)
    if (!page1.ok) return
    expect(page1.value.hits).toHaveLength(3)
    expect(page1.value.nextOffset).toBe(3)
    expect(page1.value.totalHits).toBeGreaterThanOrEqual(8)

    const page2 = searchUnlockedIndex({ index, query, offset: 3, limit: 3 })
    expect(page2.ok).toBe(true)
    if (!page2.ok) return
    expect(page2.value.offset).toBe(3)
    expect(page2.value.hits.length).toBeGreaterThan(0)

    expect(fetchSpy).not.toHaveBeenCalled()
    expect(wsSpy).not.toHaveBeenCalled()
    fetchSpy.mockRestore()
    wsSpy.mockRestore()
    index.wipe()
  })
})
