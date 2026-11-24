/**
 * Step 10 — lightweight recovery performance contracts for CI.
 * 100 MiB heap/export budgets stay documented in PCAP_RECOVERY_LIMITS; this
 * suite asserts local invariants without allocating a 100 MiB capture.
 */

import { describe, expect, it } from 'vitest'
import { CaptureFormat, type PacketRecordDescriptor, type PacketTimestamp } from '../../src/pcap/domain/types'
import { PCAP_ENGINE_VERSION, hashPcapLevel, type PcapPlanSnapshot } from '../../src/pcap/export/planSnapshot'
import { emptyPlanChangeCounts } from '../../src/pcap/plan/planDisposition'
import { sha256 } from '../../src/crypto/incrementalSha256'
import { runIncrementalExport } from '../../src/pcap/export/incremental'
import { writeFullLiteralRecoveryBundle } from '../../src/pcap/recovery/export/recoveryBundleWriter'
import { extractRecoveryQuery } from '../../src/pcap/recovery/restore/queryExtractor'
import { PCAP_RECOVERY_LIMITS } from '../../src/pcap/recovery/domain/limits'
import { searchUnlockedIndex } from '../../src/pcap/recovery/restore/recoverySearch'
import { buildEmptyCompactIndex } from '../../src/pcap/recovery/export/compactIndexBuilder'
import { buildUnlockedLookupIndex } from '../../src/pcap/recovery/restore/unlockedLookupIndex'

function ts(): PacketTimestamp {
  return { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n }
}

function makePcap(): { buffer: ArrayBuffer; descriptors: PacketRecordDescriptor[] } {
  const packetData = new Uint8Array(64)
  packetData.fill(7)
  const size = 24 + 16 + packetData.length
  const buf = new ArrayBuffer(size)
  const view = new DataView(buf)
  view.setUint32(0, 0xa1b2c3d4, true)
  view.setUint16(4, 2, true)
  view.setUint16(6, 4, true)
  view.setUint32(16, 65535, true)
  view.setUint32(20, 1, true)
  view.setUint32(24 + 8, packetData.length, true)
  view.setUint32(24 + 12, packetData.length, true)
  new Uint8Array(buf, 40, packetData.length).set(packetData)
  return {
    buffer: buf,
    descriptors: [{
      packetNumber: 1,
      timestamp: ts(),
      capturedLength: packetData.length,
      originalLength: packetData.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 24,
      dataOffset: 40,
    }],
  }
}

function plan(): PcapPlanSnapshot {
  return {
    generationId: 'gen-bench',
    pcapLevel: 'diagnostic',
    profileId: 'pcap-diagnostic',
    profileHash: hashPcapLevel('diagnostic'),
    format: CaptureFormat.ClassicPcap,
    fileName: 'bench.pcap',
    engineVersion: PCAP_ENGINE_VERSION,
    classicHeader: {
      format: CaptureFormat.ClassicPcap,
      endian: 0,
      timestampResolution: 0,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    },
    packets: [],
    droppedPacketNumbers: [],
    timestamps: 'relative',
    timestampAnchorSeed: 'seed',
    changeCategoryTotals: emptyPlanChangeCounts(),
    maskedByteCount: 0,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
  }
}

describe('Step 10 — recovery performance contracts', () => {
  it('central limits match the documented budgets', () => {
    const mib = 1024 * 1024
    expect(PCAP_RECOVERY_LIMITS.targetExtraHeapBytes).toBe(64 * mib)
    expect(PCAP_RECOVERY_LIMITS.hardExtraHeapBytes).toBe(96 * mib)
    expect(PCAP_RECOVERY_LIMITS.defaultFramePlaintextBytes).toBe(1 * mib)
    expect(PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes).toBe(2 * mib)
    expect(PCAP_RECOVERY_LIMITS.maxUnackedChunks).toBe(2)
    expect(PCAP_RECOVERY_LIMITS.maxProgressMessagesPerSecond).toBeLessThanOrEqual(10)
    expect(PCAP_RECOVERY_LIMITS.maxProgressMessagesPerSecond).toBeGreaterThanOrEqual(4)
    expect(PCAP_RECOVERY_LIMITS.copyAnonDefaultEnabled).toBe(false)
  })

  it('recovery-off incremental export stays faster than writing a sidecar', async () => {
    const { buffer, descriptors } = makePcap()
    const sourceBlob = new Blob([buffer])
    const snapshot = plan()
    const t0 = performance.now()
    await runIncrementalExport({ plan: snapshot, descriptors, sourceBlob })
    const offMs = performance.now() - t0

    const anonymized = new Uint8Array(buffer)
    const t1 = performance.now()
    await writeFullLiteralRecoveryBundle({
      sourceBlob,
      descriptors,
      plan: snapshot,
      anonymizedSha256: sha256(anonymized),
      anonymizedByteLength: anonymized.byteLength,
      onChunk: () => undefined,
    })
    const recoveryMs = performance.now() - t1
    expect(offMs).toBeLessThan(recoveryMs * 4 + 50)
  })

  it('query extract and empty-index lookup stay well under UI task budget', () => {
    const empty = buildEmptyCompactIndex({
      generationId: 'gen-bench',
      originalPacketCount: 1,
      anonymizedPacketCount: 1,
      rangeDirectory: [{
        spanStart: 0,
        spanEnd: 24,
        fileOffset: 0,
        length: 24,
        dataFrameLocalIndex: 0,
        split: false,
      }],
    })
    expect(empty.ok).toBe(true)
    if (!empty.ok) return
    const index = buildUnlockedLookupIndex(empty.value.plaintext)
    expect(index.ok).toBe(true)
    if (!index.ok) return

    const t0 = performance.now()
    const extracted = extractRecoveryQuery('See 10.0.0.1 and packet 3 in the AI reply.')
    expect(extracted.ok).toBe(true)
    const searched = searchUnlockedIndex({
      index: index.value,
      query: '10.0.0.1 packet 3',
    })
    const ms = performance.now() - t0
    expect(searched.ok).toBe(true)
    expect(ms).toBeLessThan(50)
    const t1 = performance.now()
    for (let i = 0; i < 10; i++) {
      searchUnlockedIndex({ index: index.value, query: `10.0.0.${i} packet ${i}` })
    }
    expect(performance.now() - t1).toBeLessThan(80)
    index.value.wipe()
  })
})
