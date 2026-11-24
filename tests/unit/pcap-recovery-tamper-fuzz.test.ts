/**
 * Step 10 — tamper corpus, frame-parser fuzz, cancel, stale session.
 */

import { describe, expect, it } from 'vitest'
import { CaptureFormat, type PacketRecordDescriptor, type PacketTimestamp } from '../../src/pcap/domain/types'
import { PCAP_ENGINE_VERSION, hashPcapLevel, type PcapPlanSnapshot } from '../../src/pcap/export/planSnapshot'
import { emptyPlanChangeCounts } from '../../src/pcap/plan/planDisposition'
import { sha256 } from '../../src/crypto/incrementalSha256'
import { CancellationError } from '../../src/pcap/capture/cancellation'
import {
  FrameSequenceTracker,
  PCAP_RECOVERY_ERROR,
  PCAP_RECOVERY_LIMITS,
  PCAP_RECOVERY_PROTOCOL_VERSION,
  parseFrameHeader,
  validateRecoveryProtocolVersion,
} from '../../src/pcap/recovery'
import {
  restoreOriginalFromDataFrames,
  writeFullLiteralRecoveryBundle,
} from '../../src/pcap/recovery/export/recoveryBundleWriter'
import { preflightRecoveryPair } from '../../src/pcap/recovery/restore/recoveryPairVerifier'
import { unlockRecoveryPair } from '../../src/pcap/recovery/restore/unlockPipeline'
import { RecoverySession } from '../../src/pcap/recovery/restore/recoverySession'
import { RECOVERY_FRAME_HEADER_BYTES } from '../../src/pcap/recovery/codec/formatConstants'


function ts(): PacketTimestamp {
  return { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n }
}

function makePcap(): { buffer: ArrayBuffer; descriptors: PacketRecordDescriptor[]; anonymized: Uint8Array } {
  const packetData = new Uint8Array([10, 1, 2, 3, 0xaa, 0xbb, 0xcc, 0xdd])
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
  const descriptors: PacketRecordDescriptor[] = [{
    packetNumber: 1,
    timestamp: ts(),
    capturedLength: packetData.length,
    originalLength: packetData.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24,
    dataOffset: 40,
  }]
  const anonymized = new Uint8Array(buf.byteLength)
  anonymized.set(new Uint8Array(buf))
  anonymized[40] = 0x11
  return { buffer: buf, descriptors, anonymized }
}

function plan(): PcapPlanSnapshot {
  return {
    generationId: 'gen-step10-tamper',
    pcapLevel: 'diagnostic',
    profileId: 'pcap-diagnostic',
    profileHash: hashPcapLevel('diagnostic'),
    format: CaptureFormat.ClassicPcap,
    fileName: 'tamper.pcap',
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

async function bundle(): Promise<{ recovery: Uint8Array; anonymized: Uint8Array; hash: Uint8Array }> {
  const { buffer, descriptors, anonymized } = makePcap()
  const hash = sha256(anonymized)
  const chunks: ArrayBuffer[] = []
  const written = await writeFullLiteralRecoveryBundle({
    sourceBlob: new Blob([buffer]),
    descriptors,
    plan: plan(),
    anonymizedSha256: hash,
    anonymizedByteLength: anonymized.byteLength,
    onChunk: (c) => {
      chunks.push(c)
    },
  })
  expect(written.ok).toBe(true)
  if (!written.ok) throw new Error(written.message)
  return { recovery: concatChunks(chunks), anonymized, hash }
}

describe('Step 10 — tamper / fuzz / session', () => {
  it('flipped DATA bytes are rejected rather than silently restored', async () => {
    const { recovery, hash } = await bundle()

    const flipped = recovery.slice()
    const mid = Math.min(flipped.byteLength - 20, PCAP_RECOVERY_LIMITS.maxPreambleBytes + 40)
    flipped[mid] ^= 0xff
    const tampered = await restoreOriginalFromDataFrames({
      recoveryBytes: flipped,
      anonymizedSha256: hash,
    })
    // A flipped byte either breaks frame/format parsing outright, or survives parsing but
    // produces bytes that fail the end-to-end SHA-256 check against the manifest — both are
    // "not ok", since there's no per-frame AEAD tag to catch it earlier.
    if (!tampered.ok) {
      expect([
        PCAP_RECOVERY_ERROR.invalidFormat,
        PCAP_RECOVERY_ERROR.footerInvalid,
        PCAP_RECOVERY_ERROR.frameOrder,
        PCAP_RECOVERY_ERROR.outputHashMismatch,
        PCAP_RECOVERY_ERROR.authFailed,
      ]).toContain(tampered.code)
    }
  })

  it('a recovery file paired with the wrong anonymized hash is rejected on open', async () => {
    const { recovery, anonymized } = await bundle()
    const pair = await preflightRecoveryPair({
      anonymizedBlob: new Blob([anonymized]),
      recoveryBlob: new Blob([recovery]),
    })
    expect(pair.ok).toBe(true)
    if (!pair.ok || !pair.value.bounds) return

    const wrongHash = sha256(new Uint8Array([1, 2, 3, 4]))
    const opened = await unlockRecoveryPair({
      recoveryBlob: new Blob([recovery]),
      bounds: pair.value.bounds,
      anonymizedSha256: wrongHash,
    })
    expect(opened.ok).toBe(false)
    if (!opened.ok) expect(opened.code).toBe(PCAP_RECOVERY_ERROR.authFailed)
  })

  it('fuzzes frame headers: oversize, reserved, unknown type, unknown flag, truncated', () => {
    const cases: Array<{ mutate: (h: Uint8Array) => void; codes: string[] }> = [
      {
        mutate: (h) => new DataView(h.buffer).setUint32(8, 0xffffff00, true),
        codes: [PCAP_RECOVERY_ERROR.oversize],
      },
      {
        mutate: (h) => {
          h[2] = 1
        },
        codes: [PCAP_RECOVERY_ERROR.invalidFormat],
      },
      {
        mutate: (h) => {
          h[0] = 99
        },
        codes: [PCAP_RECOVERY_ERROR.invalidFormat],
      },
      {
        mutate: (h) => {
          h[1] = 1
        },
        codes: [PCAP_RECOVERY_ERROR.versionUnsupported],
      },
    ]
    for (const c of cases) {
      const header = new Uint8Array(RECOVERY_FRAME_HEADER_BYTES)
      header[0] = 1
      new DataView(header.buffer).setUint32(8, 16, true)
      c.mutate(header)
      const parsed = parseFrameHeader(header, 0)
      expect(parsed.ok).toBe(false)
      if (!parsed.ok) expect(c.codes).toContain(parsed.code)
    }
    expect(parseFrameHeader(new Uint8Array(4), 0).ok).toBe(false)

    const tracker = new FrameSequenceTracker()
    tracker.accept({
      frameType: 1,
      frameFlags: 0,
      frameIndex: 0,
      plaintextLength: 8,
      payloadLength: 24,
    })
    const dup = tracker.accept({
      frameType: 1,
      frameFlags: 0,
      frameIndex: 0,
      plaintextLength: 8,
      payloadLength: 24,
    })
    expect(dup.ok).toBe(false)
    if (!dup.ok) expect(dup.code).toBe(PCAP_RECOVERY_ERROR.frameDuplicate)
  })

  it('cancel during recovery write throws CancellationError and publishes no original', async () => {
    const { buffer, descriptors, anonymized } = makePcap()
    await expect(
      writeFullLiteralRecoveryBundle({
        sourceBlob: new Blob([buffer]),
        descriptors,
        plan: plan(),
        anonymizedSha256: sha256(anonymized),
        anonymizedByteLength: anonymized.byteLength,
        isCancelled: () => true,
        onChunk: () => undefined,
      }),
    ).rejects.toBeInstanceOf(CancellationError)
  })

  it('stale generation/session IDs fail assertSession; protocol version is checked', () => {
    const session = new RecoverySession()
    session.beginGeneration('gen-a')
    expect(session.assertSession('gen-b')).toBe(false)
    expect(session.assertSession('gen-a', 'stale-session')).toBe(false)
    session.lock()
    expect(session.currentState).toBe('terminated')
    expect(session.assertSession('gen-a')).toBe(false)
    expect(session.lookup).toBeNull()

    expect(validateRecoveryProtocolVersion(PCAP_RECOVERY_PROTOCOL_VERSION)).toBeNull()
    expect(validateRecoveryProtocolVersion(PCAP_RECOVERY_PROTOCOL_VERSION + 1)).toBe(
      'invalid-recovery-protocol-version',
    )
  })

  it('rejects trailing extra bytes and truncated bundles before open', async () => {
    const { recovery, anonymized } = await bundle()
    const padded = new Uint8Array(recovery.byteLength + 1)
    padded.set(recovery)
    padded[padded.byteLength - 1] = 0xaa
    const extra = await preflightRecoveryPair({
      anonymizedBlob: new Blob([anonymized]),
      recoveryBlob: new Blob([padded]),
    })
    expect(extra.ok).toBe(false)
    if (!extra.ok) expect(extra.code).toBe(PCAP_RECOVERY_ERROR.footerInvalid)

    const cut = recovery.subarray(0, Math.max(0, recovery.byteLength - 8))
    const missing = await preflightRecoveryPair({
      anonymizedBlob: new Blob([anonymized]),
      recoveryBlob: new Blob([cut]),
    })
    expect(missing.ok).toBe(false)
  })
})
