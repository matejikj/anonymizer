/**
 * Step 9 — COPY_ANON provenance, codec, and differential restore vs full-literal.
 */

import { describe, expect, it } from 'vitest'
import {
  CaptureFormat,
  Endian,
  TimestampResolution,
  type PacketRecordDescriptor,
  type PacketTimestamp,
} from '../../src/pcap/domain/types'
import {
  PCAP_ENGINE_VERSION,
  hashPcapLevel,
  type PcapPlanPacket,
  type PcapPlanSnapshot,
} from '../../src/pcap/export/planSnapshot'
import { emptyPlanChangeCounts } from '../../src/pcap/plan/planDisposition'
import { bytesEqual, bytesToHex, sha256 } from '../../src/crypto/incrementalSha256'
import {
  AnonymizedProvenanceRecorder,
  COPY_ANON_MIN_RUN_BYTES,
  validateProvenanceCopies,
} from '../../src/pcap/export/anonymizedProvenance'
import { runIncrementalExport } from '../../src/pcap/export/incremental'
import {
  writeRestoreOpsFrame,
  parseRestoreOpsFrame,
  applyRestoreOpsToRange,
} from '../../src/pcap/recovery/codec/literalFrameCodec'
import {
  planRestoreOps,
  totalCopyAnonBytes,
} from '../../src/pcap/recovery/export/copyAnonPlanner'
import {
  restoreOriginalFromDataFrames,
  writeFullLiteralRecoveryBundle,
} from '../../src/pcap/recovery/export/recoveryBundleWriter'
import { preflightRecoveryPair } from '../../src/pcap/recovery/restore/recoveryPairVerifier'
import { unlockRecoveryPair } from '../../src/pcap/recovery/restore/unlockPipeline'
import { openRestoredPacket } from '../../src/pcap/recovery/restore/packetRestore'
import { streamFullRestore } from '../../src/pcap/recovery/restore/fullRestore'
import { PCAP_RECOVERY_ERROR } from '../../src/pcap/recovery/domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../../src/pcap/recovery/domain/limits'
import { GLOBAL_HEADER_SIZE } from '../../src/pcap/capture/classicPcapFraming'

const PAYLOAD_LEN = 32

function ts(n = 0): PacketTimestamp {
  return { ticks: BigInt(n) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n }
}

function makePcap(packets: number): {
  buffer: ArrayBuffer
  descriptors: PacketRecordDescriptor[]
  payloads: Uint8Array[]
} {
  const payloads = Array.from({ length: packets }, (_, i) => {
    const p = new Uint8Array(PAYLOAD_LEN)
    p.fill(0x40 + i)
    p[0] = 0xa0 + i
    p[1] = 0x01
    return p
  })
  const size = GLOBAL_HEADER_SIZE + packets * (16 + PAYLOAD_LEN)
  const buf = new ArrayBuffer(size)
  const view = new DataView(buf)
  view.setUint32(0, 0xa1b2c3d4, true)
  view.setUint16(4, 2, true)
  view.setUint16(6, 4, true)
  view.setUint32(16, 65535, true)
  view.setUint32(20, 1, true)
  const descriptors: PacketRecordDescriptor[] = []
  let offset = GLOBAL_HEADER_SIZE
  for (let i = 0; i < packets; i++) {
    view.setUint32(offset, i, true)
    view.setUint32(offset + 8, payloads[i]!.byteLength, true)
    view.setUint32(offset + 12, payloads[i]!.byteLength, true)
    new Uint8Array(buf, offset + 16, payloads[i]!.byteLength).set(payloads[i]!)
    descriptors.push({
      packetNumber: i + 1,
      timestamp: ts(i),
      capturedLength: payloads[i]!.byteLength,
      originalLength: payloads[i]!.byteLength,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: offset,
      dataOffset: offset + 16,
    })
    offset += 16 + payloads[i]!.byteLength
  }
  return { buffer: buf, descriptors, payloads }
}

function planPacket(
  index: number,
  descriptor: PacketRecordDescriptor,
  extra?: { drop?: boolean; patches?: { offset: number; data: Uint8Array }[]; truncatedLength?: number },
): PcapPlanPacket {
  return {
    index,
    packetNumber: descriptor.packetNumber,
    drop: extra?.drop ?? false,
    patches: extra?.patches ?? [],
    truncatedLength: extra?.truncatedLength,
    originalCapturedLength: descriptor.capturedLength,
    originalLength: descriptor.originalLength,
    linkType: descriptor.linkType,
    interfaceId: descriptor.interfaceId,
    sectionIndex: descriptor.sectionIndex,
    originalTimestamp: descriptor.timestamp,
    dispositionReason: extra?.drop ? 'user-requested-drop' : 'exported',
    changeCounts: emptyPlanChangeCounts(),
    maskedByteCount: extra?.patches?.[0]?.data.byteLength ?? 0,
  }
}

function planFor(
  fileName: string,
  descriptors: readonly PacketRecordDescriptor[],
  packets: readonly PcapPlanPacket[],
): PcapPlanSnapshot {
  return {
    generationId: 'gen-step9',
    pcapLevel: 'diagnostic',
    profileId: 'pcap-diagnostic',
    profileHash: hashPcapLevel('diagnostic'),
    format: CaptureFormat.ClassicPcap,
    fileName,
    engineVersion: PCAP_ENGINE_VERSION,
    classicHeader: {
      format: CaptureFormat.ClassicPcap,
      endian: Endian.Little,
      timestampResolution: TimestampResolution.Microseconds,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    },
    packets: [...packets],
    droppedPacketNumbers: packets.filter((p) => p.drop).map((p) => p.packetNumber),
    timestamps: 'relative',
    timestampAnchorSeed: 'seed-step9',
    changeCategoryTotals: emptyPlanChangeCounts(),
    maskedByteCount: 0,
    dropsByReason: {
      exported: packets.filter((p) => !p.drop).length,
      'user-requested-drop': packets.filter((p) => p.drop).length,
      blocked: 0,
    },
    dropsByProtocol: {},
  }
}

function concatChunks(chunks: readonly ArrayBuffer[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.byteLength, 0)
  const out = new Uint8Array(total)
  let o = 0
  for (const c of chunks) {
    out.set(new Uint8Array(c), o)
    o += c.byteLength
  }
  return out
}

describe('Step 9 — provenance recorder', () => {
  it('records only monotonic byte-equal payload runs above the min length', () => {
    const rec = new AnonymizedProvenanceRecorder()
    rec.recordRewrite(24)
    const original = new Uint8Array(40)
    original.fill(0x11)
    const emitted = original.slice()
    emitted[0] = 0x22
    rec.recordVerifiedCopies({
      originalPayload: original,
      emittedPayload: emitted,
      originalFileOffset: 40,
    })
    const copies = rec.finish(24 + 40, 100)
    expect(copies).not.toBeNull()
    expect(copies!.length).toBe(1)
    expect(copies![0]).toEqual({
      originalOffset: 41,
      anonymizedOffset: 25,
      length: 39,
    })
    expect(validateProvenanceCopies(copies!, 100, 64)).toBe(true)
  })

  it('does not COPY_ANON short equal runs', () => {
    const rec = new AnonymizedProvenanceRecorder()
    rec.recordRewrite(16)
    const original = new Uint8Array(COPY_ANON_MIN_RUN_BYTES - 1)
    original.fill(7)
    rec.recordVerifiedCopies({
      originalPayload: original,
      emittedPayload: original,
      originalFileOffset: 16,
    })
    expect(rec.finish(16 + original.byteLength, 40)).toEqual([])
  })

  it('rejects overlapping original offsets', () => {
    expect(
      validateProvenanceCopies(
        [
          { originalOffset: 0, anonymizedOffset: 10, length: 20 },
          { originalOffset: 10, anonymizedOffset: 40, length: 8 },
        ],
        100,
        100,
      ),
    ).toBe(false)
  })
})

describe('Step 9 — restore-op codec', () => {
  it('round-trips mixed LITERAL and COPY_ANON ops', async () => {
    const literal = new Uint8Array([1, 2, 3, 4])
    const encoded = writeRestoreOpsFrame([
      { type: 'literal', originalOffset: 0, length: 4, bytes: literal },
      { type: 'copy-anon', originalOffset: 4, length: 8, anonymizedOffset: 24 },
    ])
    expect(encoded.ok).toBe(true)
    if (!encoded.ok) return
    const parsed = parseRestoreOpsFrame(encoded.value)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(parsed.value).toHaveLength(2)
    expect(parsed.value[0]).toMatchObject({ type: 'literal', originalOffset: 0, length: 4 })
    expect(parsed.value[1]).toEqual({
      type: 'copy-anon',
      originalOffset: 4,
      length: 8,
      anonymizedOffset: 24,
    })

    const anon = new Uint8Array(40)
    anon.fill(0xab, 24, 32)
    const out = new Uint8Array(12)
    const applied = await applyRestoreOpsToRange({
      ops: parsed.value,
      rangeStart: 0,
      rangeEnd: 12,
      anonymized: anon,
      out,
    })
    expect(applied.ok).toBe(true)
    expect([...out.subarray(0, 4)]).toEqual([1, 2, 3, 4])
    expect([...out.subarray(4)]).toEqual(Array(8).fill(0xab))
  })

  it('rejects backwards COPY_ANON offsets', () => {
    const encoded = writeRestoreOpsFrame([
      { type: 'copy-anon', originalOffset: 0, length: 8, anonymizedOffset: 20 },
      { type: 'copy-anon', originalOffset: 8, length: 8, anonymizedOffset: 10 },
    ])
    expect(encoded.ok).toBe(true)
    if (!encoded.ok) return
    const parsed = parseRestoreOpsFrame(encoded.value)
    expect(parsed.ok).toBe(false)
    if (!parsed.ok) expect(parsed.code).toBe(PCAP_RECOVERY_ERROR.invalidFormat)
  })
})

describe('Step 9 — COPY_ANON vs full-literal identity', () => {
  it('falls back to full-literal when provenance is overlapping', async () => {
    const { buffer, descriptors } = makePcap(2)
    const original = new Uint8Array(buffer)
    const anonymized = original.slice()
    const hash = sha256(anonymized)
    const chunks: ArrayBuffer[] = []
    const written = await writeFullLiteralRecoveryBundle({
      sourceBlob: new Blob([buffer]),
      descriptors,
      plan: planFor('overlap.pcap', descriptors, descriptors.map((d, i) => planPacket(i, d))),
      anonymizedSha256: hash,
      anonymizedByteLength: anonymized.byteLength,
      copyAnon: true,
      provenanceCopies: [
        { originalOffset: 0, anonymizedOffset: 0, length: 20 },
        { originalOffset: 10, anonymizedOffset: 30, length: 8 },
      ],
      onChunk: (c) => {
        chunks.push(c)
      },
    })
    expect(written.ok).toBe(true)
    if (!written.ok) return
    expect(written.value.restoreEncoding).toBe('full-literal-frames-v1')
  })

  it('restores the same original SHA-256 as full-literal for patched + dropped packets', async () => {
    const { buffer, descriptors, payloads } = makePcap(3)
    const original = new Uint8Array(buffer)
    const sourceBlob = new Blob([buffer])
    const packets = [
      planPacket(0, descriptors[0]!, {
        patches: [{ offset: 0, data: new Uint8Array([0xee]) }],
      }),
      planPacket(1, descriptors[1]!, { drop: true }),
      planPacket(2, descriptors[2]!),
    ]
    const snapshot = planFor('delta.pcap', descriptors, packets)

    const provenance = new AnonymizedProvenanceRecorder()
    const exported = await runIncrementalExport({
      plan: snapshot,
      descriptors,
      sourceBlob,
      provenance,
    })
    const anonymized = concatChunks(exported.chunks)
    const copies = provenance.finish(anonymized.byteLength, original.byteLength)
    expect(copies).not.toBeNull()
    const dropped = descriptors[1]!
    const droppedStart = dropped.fileOffset
    const droppedEnd = dropped.fileOffset + 16 + dropped.capturedLength
    expect(
      copies!.every(
        (c) => c.originalOffset + c.length <= droppedStart || c.originalOffset >= droppedEnd,
      ),
    ).toBe(true)
    expect(copies!.every((c) => (c.originalOffset - GLOBAL_HEADER_SIZE) % (16 + PAYLOAD_LEN) >= 16)).toBe(
      true,
    )

    const planned = planRestoreOps(original.byteLength, copies!, anonymized.byteLength)
    expect(planned.ok).toBe(true)
    if (!planned.ok) return
    expect(totalCopyAnonBytes(planned.value)).toBeGreaterThanOrEqual(PAYLOAD_LEN - 1)

    const hash = sha256(anonymized)
    const literalChunks: ArrayBuffer[] = []
    const literal = await writeFullLiteralRecoveryBundle({
      sourceBlob,
      descriptors,
      plan: snapshot,
      anonymizedSha256: hash,
      anonymizedByteLength: anonymized.byteLength,
      onChunk: (c) => {
        literalChunks.push(c)
      },
    })
    expect(literal.ok).toBe(true)
    if (!literal.ok) return
    expect(literal.value.restoreEncoding).toBe('full-literal-frames-v1')

    const copyChunks: ArrayBuffer[] = []
    const copyAnon = await writeFullLiteralRecoveryBundle({
      sourceBlob,
      descriptors,
      plan: snapshot,
      anonymizedSha256: hash,
      anonymizedByteLength: anonymized.byteLength,
      copyAnon: true,
      provenanceCopies: copies!,
      onChunk: (c) => {
        copyChunks.push(c)
      },
    })
    expect(copyAnon.ok).toBe(true)
    if (!copyAnon.ok) return
    expect(copyAnon.value.restoreEncoding).toBe('copy-anonymized-literal-v1')
    expect(copyAnon.value.originalByteLength).toBe(original.byteLength)
    expect(bytesToHex(copyAnon.value.originalSha256)).toBe(bytesToHex(literal.value.originalSha256))

    const restoredLiteral = await restoreOriginalFromDataFrames({
      recoveryBytes: concatChunks(literalChunks),
      anonymizedSha256: hash,
    })
    const restoredCopy = await restoreOriginalFromDataFrames({
      recoveryBytes: concatChunks(copyChunks),
      anonymizedSha256: hash,
      anonymizedBytes: anonymized,
    })
    expect(restoredLiteral.ok).toBe(true)
    expect(restoredCopy.ok).toBe(true)
    if (!restoredLiteral.ok || !restoredCopy.ok) return
    expect(restoredCopy.value.manifest.restoreEncoding).toBe('copy-anonymized-literal-v1')
    expect(bytesEqual(restoredLiteral.value.original, original)).toBe(true)
    expect(bytesEqual(restoredCopy.value.original, original)).toBe(true)
    expect(bytesToHex(restoredCopy.value.originalSha256)).toBe(bytesToHex(sha256(original)))
    expect(payloads[0]![0]).toBe(0xa0)
  })

  it('COPY_ANON and full-literal restores match across random patches and drops', async () => {
    for (let round = 0; round < 8; round++) {
      const { buffer, descriptors } = makePcap(4)
      const original = new Uint8Array(buffer)
      const sourceBlob = new Blob([buffer])
      const packets = descriptors.map((d, i) => {
        if (i === 1 && round % 2 === 0) return planPacket(i, d, { drop: true })
        if (i === 0) {
          return planPacket(i, d, {
            patches: [{ offset: 0, data: new Uint8Array([0x80 + round]) }],
          })
        }
        return planPacket(i, d)
      })
      const snapshot = planFor(`prop-${round}.pcap`, descriptors, packets)
      const provenance = new AnonymizedProvenanceRecorder()
      const exported = await runIncrementalExport({
        plan: snapshot,
        descriptors,
        sourceBlob,
        provenance,
      })
      const anonymized = concatChunks(exported.chunks)
      const copies = provenance.finish(anonymized.byteLength, original.byteLength)
      const hash = sha256(anonymized)

      const literalChunks: ArrayBuffer[] = []
      const copyChunks: ArrayBuffer[] = []
      const lit = await writeFullLiteralRecoveryBundle({
        sourceBlob,
        descriptors,
        plan: snapshot,
        anonymizedSha256: hash,
        anonymizedByteLength: anonymized.byteLength,
        onChunk: (c) => {
          literalChunks.push(c)
        },
      })
      const copy = await writeFullLiteralRecoveryBundle({
        sourceBlob,
        descriptors,
        plan: snapshot,
        anonymizedSha256: hash,
        anonymizedByteLength: anonymized.byteLength,
        copyAnon: true,
        provenanceCopies: copies ?? [],
        onChunk: (c) => {
          copyChunks.push(c)
        },
      })
      expect(lit.ok && copy.ok).toBe(true)
      if (!lit.ok || !copy.ok) return
      const restoredLiteral = await restoreOriginalFromDataFrames({
        recoveryBytes: concatChunks(literalChunks),
        anonymizedSha256: hash,
        anonymizedBytes: anonymized,
      })
      const restoredCopy = await restoreOriginalFromDataFrames({
        recoveryBytes: concatChunks(copyChunks),
        anonymizedSha256: hash,
        anonymizedBytes: anonymized,
      })
      expect(restoredLiteral.ok && restoredCopy.ok).toBe(true)
      if (!restoredLiteral.ok || !restoredCopy.ok) return
      expect(bytesToHex(restoredLiteral.value.originalSha256)).toBe(bytesToHex(sha256(original)))
      expect(bytesToHex(restoredCopy.value.originalSha256)).toBe(bytesToHex(sha256(original)))
    }
  })

  it('opens a packet and full-restores without publishing a hash mismatch', async () => {
    const { buffer, descriptors } = makePcap(3)
    const original = new Uint8Array(buffer)
    const sourceBlob = new Blob([buffer])
    const packets = descriptors.map((d, i) =>
      planPacket(i, d, i === 0 ? { patches: [{ offset: 2, data: new Uint8Array([0x99]) }] } : undefined),
    )
    const snapshot = planFor('packet.pcap', descriptors, packets)
    const provenance = new AnonymizedProvenanceRecorder()
    const exported = await runIncrementalExport({ plan: snapshot, descriptors, sourceBlob, provenance })
    const anonymized = concatChunks(exported.chunks)
    const copies = provenance.finish(anonymized.byteLength, original.byteLength)
    expect(copies?.length).toBeGreaterThan(0)

    const recChunks: ArrayBuffer[] = []
    const written = await writeFullLiteralRecoveryBundle({
      sourceBlob,
      descriptors,
      plan: snapshot,
      anonymizedSha256: sha256(anonymized),
      anonymizedByteLength: anonymized.byteLength,
      copyAnon: true,
      provenanceCopies: copies!,
      onChunk: (c) => {
        recChunks.push(c)
      },
    })
    expect(written.ok && written.value.restoreEncoding).toBe('copy-anonymized-literal-v1')
    if (!written.ok) return

    const recoveryBytes = concatChunks(recChunks)
    const pair = await preflightRecoveryPair({
      anonymizedBlob: new Blob([anonymized]),
      recoveryBlob: new Blob([recoveryBytes]),
    })
    expect(pair.ok).toBe(true)
    if (!pair.ok) return
    const unlocked = await unlockRecoveryPair({
      recoveryBlob: new Blob([recoveryBytes]),
      bounds: pair.value.bounds,
      anonymizedSha256: pair.value.anonymizedSha256,
    })
    expect(unlocked.ok).toBe(true)
    if (!unlocked.ok) return

    const opened = await openRestoredPacket(
      {
        recoveryBlob: new Blob([recoveryBytes]),
        anonymizedBlob: new Blob([anonymized]),
        bounds: pair.value.bounds,
        keys: unlocked.value.keys,
        manifest: unlocked.value.manifest,
        index: unlocked.value.index,
      },
      { originalPacketNumber: 3 },
    )
    expect(opened.ok).toBe(true)
    if (!opened.ok) return
    expect(opened.value.originalPacketNumber).toBe(3)
    expect(opened.value.capturedLength).toBe(PAYLOAD_LEN)

    const out: ArrayBuffer[] = []
    const full = await streamFullRestore({
      recoveryBlob: new Blob([recoveryBytes]),
      bounds: pair.value.bounds,
      keys: unlocked.value.keys,
      manifest: unlocked.value.manifest,
      anonymizedBlob: new Blob([anonymized]),
      handlers: {
        onChunk: async (chunk) => {
          out.push(chunk)
        },
      },
    })
    expect(full.ok).toBe(true)
    if (!full.ok) return
    expect(full.value.verified).toBe(true)
    expect(bytesEqual(concatChunks(out), original)).toBe(true)
  })

  it('fail-closes full restore when COPY_ANON anonymized bytes are tampered', async () => {
    const { buffer, descriptors } = makePcap(2)
    const original = new Uint8Array(buffer)
    const sourceBlob = new Blob([buffer])
    const packets = descriptors.map((d, i) => planPacket(i, d))
    const snapshot = planFor('tamper.pcap', descriptors, packets)
    const provenance = new AnonymizedProvenanceRecorder()
    const exported = await runIncrementalExport({ plan: snapshot, descriptors, sourceBlob, provenance })
    const anonymized = concatChunks(exported.chunks)
    const copies = provenance.finish(anonymized.byteLength, original.byteLength)
    expect(copies?.length).toBeGreaterThan(0)

    const recChunks: ArrayBuffer[] = []
    const written = await writeFullLiteralRecoveryBundle({
      sourceBlob,
      descriptors,
      plan: snapshot,
      anonymizedSha256: sha256(anonymized),
      anonymizedByteLength: anonymized.byteLength,
      copyAnon: true,
      provenanceCopies: copies!,
      onChunk: (c) => {
        recChunks.push(c)
      },
    })
    expect(written.ok).toBe(true)
    if (!written.ok) return

    const tampered = anonymized.slice()
    tampered[tampered.byteLength - 1] ^= 0xff
    const restored = await restoreOriginalFromDataFrames({
      recoveryBytes: concatChunks(recChunks),
      anonymizedSha256: sha256(anonymized),
      anonymizedBytes: tampered,
    })
    expect(restored.ok).toBe(false)
    if (!restored.ok) expect(restored.code).toBe(PCAP_RECOVERY_ERROR.outputHashMismatch)
  })
})
