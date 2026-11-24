/**
 * @vitest-environment happy-dom
 *
 * UI scroll/filter performance smoke (step 3).
 * Ensures filter over large descriptor sets stays within budget without plan rebuild.
 */

import { describe, expect, it, beforeEach } from 'vitest'
import { createElement } from 'react'
import { render } from '@testing-library/react'
import { clearPcapSession, filterPacketIndices, getPacketEndpoints, DEFAULT_PCAP_FILTER } from '../../../src/pcap/ui/pcapSession'
import { type PacketEnvelope } from '../../../src/pcap/domain/types'
import { createTestPcapSessionFromPackets } from './pcapSessionTestHelpers'
import { PackedEntityOccurrenceIndex } from '../../../src/pcap/coverage/entityOccurrenceIndex'
import { PcapByteGrid } from '../../../src/pcap/ui/PcapByteGrid'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import type { DissectionNode } from '../../../src/pcap/dissection/types'

function makePacket(n: number): PacketEnvelope {
  const data = new Uint8Array(42)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data.set([10, 0, 0, 1], 26)
  data.set([10, 0, 0, 2], 30)
  return {
    packetNumber: n,
    timestamp: { ticks: BigInt(n), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('pcap UI performance smoke', () => {
  beforeEach(() => {
    clearPcapSession()
  })

  it('filters 2000 packets under 200ms without loading bytes', async () => {
    const packets = Array.from({ length: 2000 }, (_, i) => makePacket(i + 1))
    await createTestPcapSessionFromPackets({ fileName: 'perf.pcap', packets })
    const start = performance.now()
    const indices = filterPacketIndices(DEFAULT_PCAP_FILTER, 'frame.number >= 100')
    const elapsed = performance.now() - start
    expect(indices.length).toBeGreaterThan(0)
    expect(elapsed).toBeLessThan(200)
  })

  it('PF-05: hasEntity scales with log(occurrences), not linearly', () => {
    const occurrenceCount = 200_000
    const occurrences = Array.from({ length: occurrenceCount }, (_, i) => i * 2) // every other index
    const index = PackedEntityOccurrenceIndex.fromLists(new Map([['ipv4:hot-entity', occurrences]]))

    // Correctness at the edges and middle — binary search must agree with a linear scan.
    expect(index.hasEntity('ipv4:hot-entity', 0)).toBe(true)
    expect(index.hasEntity('ipv4:hot-entity', 1)).toBe(false)
    expect(index.hasEntity('ipv4:hot-entity', (occurrenceCount - 1) * 2)).toBe(true)
    expect(index.hasEntity('ipv4:hot-entity', occurrenceCount * 2)).toBe(false)
    expect(index.hasEntity('ipv4:hot-entity', occurrenceCount)).toBe(true) // mid-range even index
    expect(index.hasEntity('missing-entity', 0)).toBe(false)

    // 50,000 lookups against a 200,000-entry occurrence list: with a linear scan this is on
    // the order of 10^10 comparisons (multiple seconds); with binary search it is ~17
    // comparisons each (well under a millisecond total). The bound below is generous but would
    // be impossible to meet with the old O(occurrences) implementation.
    const start = performance.now()
    let hits = 0
    for (let i = 0; i < 50_000; i++) {
      if (index.hasEntity('ipv4:hot-entity', (i * 37) % (occurrenceCount * 2))) hits++
    }
    const elapsed = performance.now() - start
    expect(hits).toBeGreaterThan(0)
    expect(elapsed).toBeLessThan(100)
  })

  it('PF-05: getPacketEndpoints stays fast across many packets sharing one high-cardinality entity', async () => {
    const packetCount = 8000
    const packets = Array.from({ length: packetCount }, (_, i) => makePacket(i + 1))
    await createTestPcapSessionFromPackets({ fileName: 'high-cardinality.pcap', packets })

    // Simulates the coloring/scroll workload: call getPacketEndpoints once per packet, for
    // every packet in the capture. The shared 10.0.0.1/10.0.0.2 entity has `packetCount`
    // occurrences, so this previously cost O(packetCount^2) (a full entity scan + linear
    // occurrence scan per call); with the cached reverse index it is ~O(packetCount).
    const start = performance.now()
    for (let i = 0; i < packetCount; i++) {
      const ep = getPacketEndpoints(i)
      if (i === 0) {
        expect(ep.source).toMatch(/10\.0\.0\.1|—/)
        expect(ep.dest).toMatch(/10\.0\.0\.2|—/)
      }
    }
    const elapsed = performance.now() - start
    expect(elapsed).toBeLessThan(500)
  })

  it('PF-13: PcapByteGrid renders a jumbo frame virtualized and fast, without losing changeKind highlighting', () => {
    usePcapStore.getState().resetToEmpty()

    // Jumbo Ethernet frame (doc's own worst case: 65535 B, ~260,000 DOM nodes unvirtualized).
    const byteLength = 65_535
    const bytes = new Uint8Array(byteLength)
    for (let i = 0; i < byteLength; i++) bytes[i] = i & 0xff

    // A dense dissection field map (2000 fields, 32 B each) — the exact shape that made the old
    // per-byte changeKindAt scan O(bytes x fields) (65,535 x 2000 ~= 131M comparisons/render).
    const fieldMap: DissectionNode[] = []
    for (let i = 0; i * 32 < byteLength; i++) {
      fieldMap.push({
        id: `field-${i}`,
        label: `field ${i}`,
        offset: i * 32,
        length: 32,
        children: [],
        changeKind: i % 5 === 0 ? 'redacted' : 'none',
      })
    }

    const start = performance.now()
    const { container } = render(
      createElement(PcapByteGrid, {
        sources: [{ id: 'frame', label: 'Frame', bytes, fieldMap }],
        roots: [],
      }),
    )
    const elapsed = performance.now() - start

    const grid = container.querySelector('[data-testid="pcap-byte-grid"]')
    expect(grid).toBeTruthy()
    const nodeCount = grid!.querySelectorAll('*').length

    // Unvirtualized this would be ~4 DOM nodes per byte (~262,000 for 65,535 B); virtualized
    // it must stay near the visible-window size regardless of frame length.
    expect(nodeCount).toBeLessThan(3000)
    // With the O(bytes x fields) scan this comfortably exceeds several seconds; budget generous
    // for CI but far below what the old implementation could ever achieve at this scale.
    expect(elapsed).toBeLessThan(500)

    // Functional correctness: byte 0 belongs to field-0 (offset 0, changeKind 'redacted') and
    // must still carry the redacted visual class despite the memoized lookup.
    const redactedByte = grid!.querySelector('[data-byte-offset="0"].pcap-byte-grid__byte--redacted')
    expect(redactedByte).toBeTruthy()
    // Byte 32 belongs to field-1 (changeKind 'none') and must not be marked redacted.
    const plainByte = grid!.querySelector('[data-byte-offset="32"].pcap-byte-grid__byte--redacted')
    expect(plainByte).toBeFalsy()
  })
})
