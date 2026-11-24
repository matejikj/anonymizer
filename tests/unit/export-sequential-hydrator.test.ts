import { describe, expect, it } from 'vitest'
import {
  hydrateDescriptorForExport,
  createSequentialHydrator,
} from '../../src/pcap/export/incremental/hydrateSlice.ts'
import type { PacketRecordDescriptor } from '../../src/pcap/domain/types.ts'

function makeDescriptor(packetNumber: number, dataOffset: number, capturedLength: number): PacketRecordDescriptor {
  return {
    packetNumber,
    timestamp: { ticks: BigInt(packetNumber), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength,
    originalLength: capturedLength,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: dataOffset - 16,
    dataOffset,
  }
}

/** Counts Blob.slice() calls without changing behavior — same underlying Blob. */
function countingBlob(inner: Blob): { blob: Blob; sliceCalls: () => number } {
  let calls = 0
  const proxy = new Proxy(inner, {
    get(target, prop, receiver) {
      if (prop === 'slice') {
        return (...args: Parameters<Blob['slice']>) => {
          calls++
          return Reflect.apply(target.slice as (...a: unknown[]) => Blob, target, args)
        }
      }
      return Reflect.get(target, prop, receiver)
    },
  })
  return { blob: proxy, sliceCalls: () => calls }
}

describe('PF-09: sequential export hydrator', () => {
  it('produces byte-identical envelopes to the per-packet hydrator, in file order', async () => {
    const packetCount = 200
    const packetLen = 64
    const bytes = new Uint8Array(packetCount * packetLen)
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 7 + 3) & 0xff
    const blob = new Blob([bytes])

    const descriptors: PacketRecordDescriptor[] = Array.from({ length: packetCount }, (_, i) =>
      makeDescriptor(i, i * packetLen, packetLen),
    )

    const hydrateNext = createSequentialHydrator(blob)
    for (const d of descriptors) {
      const sequential = await hydrateNext(d)
      const stateless = await hydrateDescriptorForExport(blob, d)
      expect([...sequential.data]).toEqual([...stateless.data])
      expect(sequential.data.length).toBe(packetLen)
    }
  })

  it('reuses the read-ahead window instead of one Blob.slice() call per packet', async () => {
    const packetCount = 500
    const packetLen = 32 // well under the 64 KiB window
    const bytes = new Uint8Array(packetCount * packetLen)
    const realBlob = new Blob([bytes])
    const { blob, sliceCalls } = countingBlob(realBlob)

    const descriptors: PacketRecordDescriptor[] = Array.from({ length: packetCount }, (_, i) =>
      makeDescriptor(i, i * packetLen, packetLen),
    )

    const hydrateNext = createSequentialHydrator(blob)
    for (const d of descriptors) {
      await hydrateNext(d)
    }

    // All 500 packets (16,000 bytes) fit in a single 64 KiB read-ahead window, so this
    // should cost one Blob.slice() call, not 500 — the whole point of PF-09.
    expect(sliceCalls()).toBeLessThan(5)
  })

  it('falls back correctly (never wrong, just no reuse) for out-of-order descriptors', async () => {
    const packetLen = 32
    const bytes = new Uint8Array(10 * packetLen)
    for (let i = 0; i < bytes.length; i++) bytes[i] = i & 0xff
    const blob = new Blob([bytes])

    // Deliberately reversed file order.
    const descriptors = Array.from({ length: 10 }, (_, i) => makeDescriptor(i, (9 - i) * packetLen, packetLen))

    const hydrateNext = createSequentialHydrator(blob)
    for (const d of descriptors) {
      const sequential = await hydrateNext(d)
      const stateless = await hydrateDescriptorForExport(blob, d)
      expect([...sequential.data]).toEqual([...stateless.data])
    }
  })
})
