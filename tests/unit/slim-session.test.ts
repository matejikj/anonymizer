import { describe, expect, it, beforeEach } from 'vitest'
import { ByteBudgetLru } from '../../src/pcap/preview/byteBudgetLru'
import { PCAP_PREVIEW_LIMITS } from '../../src/domain/capabilityContract'
import {
  cancelPendingPreviews,
  fetchPacketPreview,
  getPreviewLruStats,
  resetPreviewController,
} from '../../src/pcap/preview/pcapPreviewController'
import { clearPcapSession } from '../../src/pcap/ui/pcapSession'
import { createTestPcapSessionFromPackets } from '../pcap/unit/pcapSessionTestHelpers'
import { CaptureFormat, type PacketEnvelope } from '../../src/pcap/domain/types'
import { onPcapSessionClosed } from '../../src/pcap/ui/pcapSessionLifecycle'

function packet(n: number, size: number): PacketEnvelope {
  const data = new Uint8Array(size)
  data[14] = 0x45
  data[26] = 192
  data[27] = 168
  data[28] = 1
  data[29] = 10
  data[30] = 10
  data[31] = 0
  data[32] = 0
  data[33] = 1
  return {
    packetNumber: n,
    timestamp: { ticks: BigInt(n), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: size,
    originalLength: size,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('Stage 9 preview LRU', () => {
  it('evicts entries when byte budget exceeded', () => {
    const lru = new ByteBudgetLru<number, Uint8Array>(100)
    lru.set(1, new Uint8Array(60), 60)
    lru.set(2, new Uint8Array(60), 60)
    expect(lru.get(1)).toBeUndefined()
    expect(lru.get(2)?.length).toBe(60)
    expect(lru.stats().bytesUsed).toBeLessThanOrEqual(100)
  })

  it('fetchPacketPreview respects LRU byte budget', async () => {
    clearPcapSession()
    const packets = [packet(1, 512), packet(2, 512), packet(3, 512)]
    const session = await createTestPcapSessionFromPackets({ fileName: 'lru.pcap', packets })
    resetPreviewController(session.generation)

    await fetchPacketPreview(session, 0)
    await fetchPacketPreview(session, 1)
    await fetchPacketPreview(session, 2)

    const stats = getPreviewLruStats()
    expect(stats.bytesUsed).toBeLessThanOrEqual(PCAP_PREVIEW_LIMITS.lruByteBudget)
  })

  it('onPcapSessionClosed clears LRU and pending previews', async () => {
    const session = await createTestPcapSessionFromPackets({
      fileName: 'close.pcap',
      packets: [packet(1, 64)],
    })
    resetPreviewController(session.generation)
    void fetchPacketPreview(session, 0)
    onPcapSessionClosed()
    cancelPendingPreviews()
    expect(getPreviewLruStats().entries).toBe(0)
  })
})

describe('Stage 9 architecture guard', () => {
  it('pcapLoadController does not use full-buffer sync analyze path', async () => {
    const { readFile } = await import('node:fs/promises')
    const { fileURLToPath } = await import('node:url')
    const path = fileURLToPath(new URL('../../src/pcap/ui/pcapLoadController.ts', import.meta.url))
    const src = await readFile(path, 'utf8')
    expect(src).not.toMatch(/analyzePackets\s*\(/)
    expect(src).not.toMatch(/runSessionSanitization/)
    expect(src).not.toMatch(/readCaptureIncremental/)
    expect(src).toContain('orchestrateViaWorkers')
  })

  it('slim session has no packets array field', async () => {
    const session = await createTestPcapSessionFromPackets({
      fileName: 'slim.pcap',
      packets: [packet(1, 42)],
    })
    expect(session.descriptors.length).toBe(1)
    expect('packets' in session).toBe(false)
    expect(session.format).toBe(CaptureFormat.ClassicPcap)
  })
})
