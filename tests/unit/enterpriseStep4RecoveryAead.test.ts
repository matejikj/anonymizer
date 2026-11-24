/**
 * Enterprise step 4 — plaintext recovery: SHA verify chain, round-trip both profiles.
 */

import { describe, expect, it } from 'vitest'
import { bytesEqual, bytesToHex, sha256 } from '../../src/crypto/incrementalSha256'
import {
  CaptureFormat,
  Endian,
  TimestampResolution,
  type PacketEnvelope,
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
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import {
  restoreOriginalFromDataFrames,
  writeFullLiteralRecoveryBundle,
} from '../../src/pcap/recovery/export/recoveryBundleWriter'
import { parsePreamble } from '../../src/pcap/recovery/codec/preambleCodec'
import {
  RECOVERY_ENCRYPTED_FORMAT_VERSION,
  RECOVERY_ENCRYPTED_UNSUPPORTED_MESSAGE,
  RECOVERY_FORMAT_VERSION,
  RECOVERY_PREAMBLE_LENGTH,
} from '../../src/pcap/recovery/codec/formatConstants'
import { PCAP_RECOVERY_ERROR } from '../../src/pcap/recovery/domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../../src/pcap/recovery/domain/limits'

function ts(n = 0): PacketTimestamp {
  return { ticks: BigInt(1_700_000_000 + n) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n }
}

function envelope(n: number, data: Uint8Array, fileOffset: number): PacketEnvelope {
  return {
    packetNumber: n,
    timestamp: ts(n),
    capturedLength: data.byteLength,
    originalLength: data.byteLength,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset,
    data,
  }
}

function classicHeader() {
  return {
    magic: 0xa1b2c3d4,
    versionMajor: 2,
    versionMinor: 4,
    thisZone: 0,
    sigFigs: 0,
    snapLen: 65535,
    network: 1,
    endian: Endian.Little,
    timestampResolution: TimestampResolution.Microseconds,
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

function plan(level: 'diagnostic' | 'high-privacy', fileName: string, packets: PcapPlanPacket[]): PcapPlanSnapshot {
  return {
    generationId: `gen-s4-${level}`,
    pcapLevel: level,
    profileId: `pcap-${level}`,
    profileHash: hashPcapLevel(level),
    format: CaptureFormat.ClassicPcap,
    fileName,
    engineVersion: PCAP_ENGINE_VERSION,
    packets,
    droppedPacketNumbers: [],
    timestamps: 'relative',
    timestampAnchorSeed: 'seed',
    changeCategoryTotals: emptyPlanChangeCounts(),
    maskedByteCount: 0,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
  }
}

function descriptorsFrom(pkts: PacketEnvelope[]): PacketRecordDescriptor[] {
  return pkts.map((pkt) => ({
    packetNumber: pkt.packetNumber,
    timestamp: pkt.timestamp,
    capturedLength: pkt.capturedLength,
    originalLength: pkt.originalLength,
    linkType: pkt.linkType,
    interfaceId: pkt.interfaceId,
    sectionIndex: pkt.sectionIndex,
    fileOffset: pkt.fileOffset,
    dataOffset: pkt.fileOffset + 16,
  }))
}

async function writeRecovery(input: {
  source: Uint8Array
  descriptors: readonly PacketRecordDescriptor[]
  plan: PcapPlanSnapshot
  anonymized: Uint8Array
}): Promise<Uint8Array> {
  const chunks: ArrayBuffer[] = []
  const written = await writeFullLiteralRecoveryBundle({
    sourceBlob: new Blob([input.source]),
    descriptors: input.descriptors,
    plan: input.plan,
    anonymizedSha256: sha256(input.anonymized),
    anonymizedByteLength: input.anonymized.byteLength,
    onChunk: (c) => {
      chunks.push(c)
    },
  })
  expect(written.ok).toBe(true)
  if (!written.ok) throw new Error(written.message)
  return concatChunks(chunks)
}

describe('enterprise step 4 — plaintext recovery', () => {
  it('publicHeader has no sourceSHA256; format is v4 plaintext', async () => {
    const payload = new Uint8Array(32).fill(0x42)
    payload[0] = 0xa0
    const pkts = [envelope(1, payload, 24)]
    const original = new Uint8Array(writeClassicPcap({ header: classicHeader(), packets: pkts }))
    const descriptors = descriptorsFrom(pkts)
    const packets: PcapPlanPacket[] = descriptors.map((d, i) => ({
      index: i,
      packetNumber: d.packetNumber,
      drop: false,
      patches: [],
      truncatedLength: undefined,
      coverage: [],
      issues: [],
    }))
    const snap = plan('diagnostic', 'opaque.pcap', packets)
    const anonymized = original.slice()
    anonymized[24 + 16] = 0xee
    const recovery = await writeRecovery({ source: original, descriptors, plan: snap, anonymized })

    const preamble = parsePreamble(recovery)
    expect(preamble.ok).toBe(true)
    if (!preamble.ok) return
    expect(preamble.value.formatVersion).toBe(RECOVERY_FORMAT_VERSION)
    expect(preamble.value.headerLength).toBe(RECOVERY_PREAMBLE_LENGTH)
    const header = recovery.subarray(0, preamble.value.headerLength)
    const sourceHash = sha256(original)
    expect(bytesToHex(header)).not.toContain(bytesToHex(sourceHash))
  })

  it('rejects legacy encrypted format version with Czech message', () => {
    const header = new Uint8Array(RECOVERY_PREAMBLE_LENGTH)
    header.set(new TextEncoder().encode('RNDPCAPR'), 0)
    const view = new DataView(header.buffer)
    view.setUint16(8, RECOVERY_ENCRYPTED_FORMAT_VERSION, true)
    view.setUint16(10, RECOVERY_ENCRYPTED_FORMAT_VERSION, true)
    view.setUint16(12, RECOVERY_PREAMBLE_LENGTH, true)
    const parsed = parsePreamble(header)
    expect(parsed.ok).toBe(false)
    if (!parsed.ok) {
      expect(parsed.code).toBe(PCAP_RECOVERY_ERROR.versionUnsupported)
      expect(parsed.message).toBe(RECOVERY_ENCRYPTED_UNSUPPORTED_MESSAGE)
    }
  })

  it('round-trip both profiles: restored SHA256 == source', async () => {
    for (const level of ['diagnostic', 'high-privacy'] as const) {
      const payload = new Uint8Array(48).fill(level === 'diagnostic' ? 0x11 : 0x22)
      const pkts = [envelope(1, payload, 24)]
      const original = new Uint8Array(writeClassicPcap({ header: classicHeader(), packets: pkts }))
      const descriptors = descriptorsFrom(pkts)
      const packets: PcapPlanPacket[] = descriptors.map((d, i) => ({
        index: i,
        packetNumber: d.packetNumber,
        drop: false,
        patches: [],
        truncatedLength: undefined,
        coverage: [],
        issues: [],
      }))
      const snap = plan(level, `${level}.pcap`, packets)
      const anonymized = original.slice()
      anonymized[40] ^= 0xff
      const recovery = await writeRecovery({ source: original, descriptors, plan: snap, anonymized })
      const restored = await restoreOriginalFromDataFrames({
        recoveryBytes: recovery,
        anonymizedSha256: sha256(anonymized),
      })
      expect(restored.ok).toBe(true)
      if (!restored.ok) return
      expect(bytesEqual(restored.value.original, original)).toBe(true)
      expect(bytesEqual(restored.value.originalSha256, sha256(original))).toBe(true)
      expect(restored.value.manifest.pcapLevel).toBe(level)
    }
  })

  it('bad anonymized hash fails closed', async () => {
    const payload = new Uint8Array(16).fill(0x55)
    const pkts = [envelope(1, payload, 24)]
    const original = new Uint8Array(writeClassicPcap({ header: classicHeader(), packets: pkts }))
    const descriptors = descriptorsFrom(pkts)
    const packets: PcapPlanPacket[] = descriptors.map((d, i) => ({
      index: i,
      packetNumber: d.packetNumber,
      drop: false,
      patches: [],
      truncatedLength: undefined,
      coverage: [],
      issues: [],
    }))
    const snap = plan('diagnostic', 'hash.pcap', packets)
    const anonymized = original.slice()
    const recovery = await writeRecovery({ source: original, descriptors, plan: snap, anonymized })
    const badHash = sha256(anonymized)
    badHash[0] ^= 0xff
    const restored = await restoreOriginalFromDataFrames({
      recoveryBytes: recovery,
      anonymizedSha256: badHash,
    })
    expect(restored.ok).toBe(false)
    if (!restored.ok) {
      expect([PCAP_RECOVERY_ERROR.pairMismatch, PCAP_RECOVERY_ERROR.authFailed]).toContain(restored.code)
    }
  })

  it('preamble length stays within PCAP_RECOVERY_LIMITS.maxPreambleBytes', () => {
    expect(PCAP_RECOVERY_LIMITS.maxPreambleBytes).toBeGreaterThanOrEqual(RECOVERY_PREAMBLE_LENGTH)
  })
})
