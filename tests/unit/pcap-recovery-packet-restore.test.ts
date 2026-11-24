/**
 * Step 8 — packet open / mini-capture / full restore without publishing unverified output.
 */

import { describe, expect, it } from 'vitest'
import { CaptureFormat, type PacketRecordDescriptor, type PacketTimestamp } from '../../src/pcap/domain/types'
import { PCAP_ENGINE_VERSION, hashPcapLevel, type PcapPlanSnapshot } from '../../src/pcap/export/planSnapshot'
import { emptyPlanChangeCounts } from '../../src/pcap/plan/planDisposition'
import { bytesEqual, bytesToHex, sha256 } from '../../src/crypto/incrementalSha256'
import { writeFullLiteralRecoveryBundle } from '../../src/pcap/recovery/export/recoveryBundleWriter'
import { preflightRecoveryPair } from '../../src/pcap/recovery/restore/recoveryPairVerifier'
import { unlockRecoveryPair } from '../../src/pcap/recovery/restore/unlockPipeline'
import { openRestoredPacket, restorePacketMiniCapture } from '../../src/pcap/recovery/restore/packetRestore'
import { streamFullRestore } from '../../src/pcap/recovery/restore/fullRestore'
import { createDecryptedFrameCache } from '../../src/pcap/recovery/restore/dataFrameDecrypt'
import { PCAP_RECOVERY_ERROR } from '../../src/pcap/recovery/domain/errors'
import { RECOVERY_FRAME_HEADER_BYTES } from '../../src/pcap/recovery/codec/formatConstants'
import { probeClassicPcap, GLOBAL_HEADER_SIZE } from '../../src/pcap/capture/classicPcapFraming'

function ts(): PacketTimestamp {
  return { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n }
}

function makePcap(packets: number): {
  buffer: ArrayBuffer
  descriptors: PacketRecordDescriptor[]
  payloads: Uint8Array[]
} {
  const payloads = Array.from({ length: packets }, (_, i) => new Uint8Array([0xa0 + i, 1, 2, 3, 4, 5, 6, 7]))
  const size = 24 + packets * (16 + 8)
  const buf = new ArrayBuffer(size)
  const view = new DataView(buf)
  view.setUint32(0, 0xa1b2c3d4, true)
  view.setUint16(4, 2, true)
  view.setUint16(6, 4, true)
  view.setUint32(16, 65535, true)
  view.setUint32(20, 1, true)
  const descriptors: PacketRecordDescriptor[] = []
  let offset = 24
  for (let i = 0; i < packets; i++) {
    view.setUint32(offset + 8, payloads[i]!.byteLength, true)
    view.setUint32(offset + 12, payloads[i]!.byteLength, true)
    new Uint8Array(buf, offset + 16, payloads[i]!.byteLength).set(payloads[i]!)
    descriptors.push({
      packetNumber: i + 1,
      timestamp: ts(),
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

function plan(): PcapPlanSnapshot {
  return {
    generationId: 'gen-step8',
    pcapLevel: 'diagnostic',
    profileId: 'pcap-diagnostic',
    profileHash: hashPcapLevel('diagnostic'),
    format: CaptureFormat.ClassicPcap,
    fileName: 'step8.pcap',
    engineVersion: PCAP_ENGINE_VERSION,
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

async function buildUnlocked() {
  const { buffer, descriptors, payloads } = makePcap(3)
  const original = new Uint8Array(buffer)
  const anonymized = original.slice()
  anonymized[40] = 0x11
  const anonymizedSha256 = sha256(anonymized)
  const chunks: ArrayBuffer[] = []
  const written = await writeFullLiteralRecoveryBundle({
    sourceBlob: new Blob([buffer]),
    descriptors,
    plan: plan(),
    anonymizedSha256,
    anonymizedByteLength: anonymized.byteLength,
    maxPlaintextBytes: 8,
    onChunk: (b) => {
      chunks.push(b)
    },
  })
  expect(written.ok).toBe(true)
  if (!written.ok) throw new Error(written.message)

  const recoveryBlob = new Blob([concatChunks(chunks)])
  const anonymizedBlob = new Blob([anonymized])
  const pre = await preflightRecoveryPair({ anonymizedBlob, recoveryBlob })
  expect(pre.ok).toBe(true)
  if (!pre.ok) throw new Error(pre.message)

  const unlocked = await unlockRecoveryPair({
    recoveryBlob,
    bounds: pre.value.bounds,
      anonymizedSha256: pre.value.anonymizedSha256!,
  })
  expect(unlocked.ok).toBe(true)
  if (!unlocked.ok) throw new Error(unlocked.message)

  return {
    original,
    payloads,
    descriptors,
    recoveryBlob,
    anonymizedBlob,
    anonymizedSha256: pre.value.anonymizedSha256!,
    bounds: pre.value.bounds,
    unlocked: unlocked.value,
    dataFrameCount: written.value.dataFrameCount,
  }
}

describe('Step 8 — open packet without full restore', () => {
  it('opens one packet without restoring the whole capture', async () => {
    const ctx = await buildUnlocked()
    const cache = createDecryptedFrameCache()

    const opened = await openRestoredPacket(
      {
        recoveryBlob: ctx.recoveryBlob,
        anonymizedBlob: ctx.anonymizedBlob,
        bounds: ctx.bounds,
        manifest: ctx.unlocked.manifest,
        index: ctx.unlocked.index,
        keys: ctx.unlocked.keys,
        cache,
      },
      { originalPacketNumber: 1 },
    )
    if (!opened.ok) {
      throw new Error(`${opened.code}: ${opened.message}`)
    }
    expect(opened.value.originalPacketNumber).toBe(1)
    expect(opened.value.miniCaptureDerived).toBe(true)
    expect(new Uint8Array(opened.value.originalPayload)).toEqual(ctx.payloads[0])
    expect(opened.value.originalPayload.byteLength).toBeLessThan(ctx.original.byteLength)
    expect(ctx.dataFrameCount).toBeGreaterThan(1)

    const later = await openRestoredPacket(
      {
        recoveryBlob: ctx.recoveryBlob,
        anonymizedBlob: ctx.anonymizedBlob,
        bounds: ctx.bounds,
        manifest: ctx.unlocked.manifest,
        index: ctx.unlocked.index,
        keys: ctx.unlocked.keys,
        cache,
      },
      { originalPacketNumber: 3 },
    )
    expect(later.ok).toBe(true)
    if (!later.ok) return
    expect(new Uint8Array(later.value.originalPayload)).toEqual(ctx.payloads[2])

    const chunks: ArrayBuffer[] = []
    const full = await streamFullRestore({
      recoveryBlob: ctx.recoveryBlob,
      bounds: ctx.bounds,
      manifest: ctx.unlocked.manifest,
      keys: ctx.unlocked.keys,
      cache,
      handlers: {
        onChunk: async (chunk) => {
          chunks.push(chunk)
        },
      },
    })
    expect(full.ok).toBe(true)
    if (!full.ok) return
    expect(full.value.verified).toBe(true)
    expect(full.value.byteLength).toBe(ctx.original.byteLength)
    expect(full.value.sha256Hex).toBe(bytesToHex(sha256(ctx.original)))
    const restored = concatChunks(chunks)
    expect(bytesEqual(restored, ctx.original)).toBe(true)

    ctx.unlocked.index.wipe()
    cache.wipe()
  })

  it('builds a derived mini-capture that is valid PCAP but not the full original', async () => {
    const ctx = await buildUnlocked()
    const mini = await restorePacketMiniCapture(
      {
        recoveryBlob: ctx.recoveryBlob,
        anonymizedBlob: ctx.anonymizedBlob,
        bounds: ctx.bounds,
        manifest: ctx.unlocked.manifest,
        index: ctx.unlocked.index,
        keys: ctx.unlocked.keys,
      },
      { originalPacketNumber: 3 },
    )
    expect(mini.ok).toBe(true)
    if (!mini.ok) return
    expect(mini.value.summary.kind).toBe('mini-capture')
    expect(mini.value.summary.verified).toBe(true)
    expect(mini.value.bytes.byteLength).toBeLessThan(ctx.original.byteLength)
    expect(mini.value.bytes.byteLength).toBeGreaterThan(GLOBAL_HEADER_SIZE + 16)
    const magic = new DataView(
      mini.value.bytes.buffer,
      mini.value.bytes.byteOffset,
      4,
    ).getUint32(0, true)
    expect(probeClassicPcap(magic)).not.toBeNull()
    expect(bytesEqual(mini.value.bytes, ctx.original)).toBe(false)

    ctx.unlocked.index.wipe()
  })
})

describe('Step 8 — fail-closed full restore', () => {
  it('does not treat a tampered DATA frame as a verified original', async () => {
    const ctx = await buildUnlocked()
    const raw = new Uint8Array(await ctx.recoveryBlob.arrayBuffer())
    // Flip a byte inside the first DATA frame payload (after preamble + header).
    const dataStart = ctx.bounds.preamble.headerLength + RECOVERY_FRAME_HEADER_BYTES + 4
    raw[dataStart] = (raw[dataStart]! ^ 0xff) & 0xff
    const tampered = new Blob([raw])

    const leaked: ArrayBuffer[] = []
    const full = await streamFullRestore({
      recoveryBlob: tampered,
      bounds: ctx.bounds,
      manifest: ctx.unlocked.manifest,
      handlers: {
        onChunk: async (chunk) => {
          leaked.push(chunk)
        },
      },
    })
    expect(full.ok).toBe(false)
    if (full.ok) return
    expect([
      PCAP_RECOVERY_ERROR.authFailed,
      PCAP_RECOVERY_ERROR.invalidFormat,
      PCAP_RECOVERY_ERROR.frameOrder,
      PCAP_RECOVERY_ERROR.frameMissing,
      PCAP_RECOVERY_ERROR.outputHashMismatch,
      PCAP_RECOVERY_ERROR.outputLengthMismatch,
    ]).toContain(full.code)
    // Caller must discard leaked chunks — this API never returns verified:true.
    ctx.unlocked.index.wipe()
  })
})
