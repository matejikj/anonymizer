import { describe, expect, it } from 'vitest'
import { planToWireExport, planFromWire } from '../../src/pcap/processing/planWireAdapter.ts'
import { emptyPlanChangeCounts } from '../../src/pcap/plan/planDisposition.ts'
import { CaptureFormat } from '../../src/pcap/domain/types.ts'
import type { PcapPlanSnapshot, PcapPlanPacket } from '../../src/pcap/export/planSnapshot.ts'

function makePacket(index: number, patchCount: number): PcapPlanPacket {
  const patches = Array.from({ length: patchCount }, (_, i) => ({
    offset: i * 4,
    data: new Uint8Array([index & 0xff, i & 0xff, 0xaa, 0xbb]),
  }))
  return {
    index,
    packetNumber: index,
    drop: false,
    patches,
    originalCapturedLength: 64,
    originalLength: 64,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    originalTimestamp: { ticks: BigInt(index), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    dispositionReason: 'exported',
    changeCounts: emptyPlanChangeCounts(),
    maskedByteCount: 0,
  }
}

function makePlan(packetCount: number, patchesPerPacket: number): PcapPlanSnapshot {
  return {
    generationId: 'gen-1',
    pcapLevel: 'diagnostic',
    profileId: 'diagnostic',
    profileHash: 'hash-1',
    policyHash: 'hash-1',
    format: CaptureFormat.ClassicPcap,
    fileName: 'test.pcap',
    engineVersion: '1.0.0',
    packets: Array.from({ length: packetCount }, (_, i) => makePacket(i, patchesPerPacket)),
    droppedPacketNumbers: [],
    timestamps: 'relative',
    timestampAnchorSeed: 'seed-1',
    changeCategoryTotals: emptyPlanChangeCounts(),
    maskedByteCount: 0,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
  }
}

describe('PF-02/perf: planToWireExport consolidated patch buffer', () => {
  it('packs every patch into ONE shared buffer and transfers exactly that one buffer', () => {
    // Real-45MB-capture regression: giving each patch its own ArrayBuffer produced millions
    // of transfer-list entries in a single postMessage() call, which effectively hung the app
    // (transfer-list processing has real per-item overhead). One shared buffer must be used
    // regardless of patch count.
    const plan = makePlan(50, 3)
    const totalPatches = 50 * 3
    const { wire, transfers } = planToWireExport(plan)

    expect(transfers.length).toBe(1)
    expect(transfers[0]).toBe(wire.patchData)

    let seen = 0
    for (const pkt of wire.packets) {
      for (const patch of pkt.patches) {
        expect(patch.byteOffset).toBeGreaterThanOrEqual(0)
        expect(patch.byteOffset + patch.length).toBeLessThanOrEqual(wire.patchData.byteLength)
        seen += 1
      }
    }
    expect(seen).toBe(totalPatches)
  })

  it('round-trips patch bytes through wire + back without loss, duplication, or reordering', () => {
    const plan = makePlan(20, 4)
    const { wire } = planToWireExport(plan)
    const restored = planFromWire(wire, 'diagnostic')

    expect(restored.packets.length).toBe(plan.packets.length)
    for (let i = 0; i < plan.packets.length; i++) {
      const original = plan.packets[i]!
      const back = restored.packets[i]!
      expect(back.patches.length).toBe(original.patches.length)
      for (let j = 0; j < original.patches.length; j++) {
        expect(back.patches[j]!.offset).toBe(original.patches[j]!.offset)
        expect([...back.patches[j]!.data]).toEqual([...original.patches[j]!.data])
      }
    }
  })

  it('two different patches never alias the same bytes in the shared buffer', () => {
    // Guards against an off-by-one in the packing cursor that could make two patches'
    // byteOffset/length ranges overlap, silently corrupting one packet's export with another's.
    const plan = makePlan(30, 5)
    const { wire } = planToWireExport(plan)
    const ranges: Array<[number, number]> = []
    for (const pkt of wire.packets) {
      for (const patch of pkt.patches) ranges.push([patch.byteOffset, patch.byteOffset + patch.length])
    }
    ranges.sort((a, b) => a[0] - b[0])
    for (let i = 1; i < ranges.length; i++) {
      expect(ranges[i]![0]).toBeGreaterThanOrEqual(ranges[i - 1]![1])
    }
  })

  it('produces one (empty) shared buffer and no patches for an all-drop plan', () => {
    const plan = makePlan(5, 0)
    const { wire, transfers } = planToWireExport(plan)
    expect(transfers.length).toBe(1)
    expect(wire.patchData.byteLength).toBe(0)
    expect(wire.packets.every((p) => p.patches.length === 0)).toBe(true)
  })

  it('scales to a large patch count without allocating a transfer-list entry per patch', () => {
    // At real-capture scale (millions of patches) this is the whole point of the fix — assert
    // the invariant directly rather than relying on wall-clock timing.
    const plan = makePlan(2000, 50) // 100,000 patches
    const { transfers } = planToWireExport(plan)
    expect(transfers.length).toBe(1)
  })
})
