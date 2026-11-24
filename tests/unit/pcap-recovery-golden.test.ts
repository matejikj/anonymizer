/**
 * Step 10 — golden corpus: recovery-on/off anonymized SHA-256 match,
 * restored original is byte-identical for classic PCAP and PCAPNG.
 */

import { describe, expect, it } from 'vitest'
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
import { bytesEqual, bytesToHex, sha256 } from '../../src/crypto/incrementalSha256'
import { runIncrementalExport } from '../../src/pcap/export/incremental'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import { writePcapng } from '../../src/pcap/capture/pcapngWriter'
import {
  restoreOriginalFromDataFrames,
  writeFullLiteralRecoveryBundle,
} from '../../src/pcap/recovery/export/recoveryBundleWriter'
import { AnonymizedProvenanceRecorder } from '../../src/pcap/export/anonymizedProvenance'
import { PCAP_RECOVERY_LIMITS } from '../../src/pcap/recovery/domain/limits'


function ts(n = 0): PacketTimestamp {
  return { ticks: BigInt(1_700_000_000 + n) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n }
}

function payload(fill: number, len = 32): Uint8Array {
  const p = new Uint8Array(len)
  p.fill(fill)
  p[0] = 0xa0
  p[1] = fill
  return p
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

function firstDifferingOffset(a: Uint8Array, b: Uint8Array): number | null {
  const n = Math.min(a.byteLength, b.byteLength)
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return i
  }
  if (a.byteLength !== b.byteLength) return n
  return null
}

function classicHeader(
  extra?: Partial<{ endian: Endian; timestampResolution: TimestampResolution }>,
) {
  return {
    format: CaptureFormat.ClassicPcap,
    endian: extra?.endian ?? Endian.Little,
    timestampResolution: extra?.timestampResolution ?? TimestampResolution.Microseconds,
    versionMajor: 2,
    versionMinor: 4,
    snapLen: 65535,
    linkType: 1,
    tzOffset: 0,
    sigfigs: 0,
  } as const
}

function planPacket(
  index: number,
  descriptor: PacketRecordDescriptor,
  extra?: {
    drop?: boolean
    patches?: { offset: number; data: Uint8Array }[]
    truncatedLength?: number
  },
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

function snapshot(input: {
  fileName: string
  format: typeof CaptureFormat.ClassicPcap | typeof CaptureFormat.Pcapng
  level: 'diagnostic' | 'high-privacy'
  packets: readonly PcapPlanPacket[]
  descriptors: readonly PacketRecordDescriptor[]
  classic?: ReturnType<typeof classicHeader>
  pcapngSections?: PcapPlanSnapshot['pcapngSections']
  pcapngInterfaces?: PcapPlanSnapshot['pcapngInterfaces']
}): PcapPlanSnapshot {
  const levelHash = hashPcapLevel(input.level)
  return {
    generationId: `gen-golden-${input.fileName}`,
    pcapLevel: input.level,
    profileId: `pcap-${input.level}`,
    profileHash: levelHash,
    policyHash: levelHash,
    format: input.format,
    fileName: input.fileName,
    engineVersion: PCAP_ENGINE_VERSION,
    classicHeader:
      input.format === CaptureFormat.ClassicPcap ? (input.classic ?? classicHeader()) : undefined,
    pcapngSections:
      input.format === CaptureFormat.Pcapng
        ? (input.pcapngSections ?? [{
            sectionIndex: 0,
            endian: Endian.Little,
            versionMajor: 1,
            versionMinor: 0,
            sectionLength: -1n,
          }])
        : undefined,
    pcapngInterfaces:
      input.format === CaptureFormat.Pcapng
        ? (input.pcapngInterfaces ?? [{
            interfaceId: 0,
            sectionIndex: 0,
            linkType: 1,
            snapLen: 65535,
            tsResol: TimestampResolution.Microseconds,
            tsResolValue: 6,
            tsOffset: 0n,
          }])
        : undefined,
    packets: [...input.packets],
    droppedPacketNumbers: input.packets.filter((p) => p.drop).map((p) => p.packetNumber),
    timestamps: 'relative',
    timestampAnchorSeed: 'golden-seed',
    changeCategoryTotals: emptyPlanChangeCounts(),
    maskedByteCount: 0,
    dropsByReason: {
      exported: input.packets.filter((p) => !p.drop).length,
      'user-requested-drop': input.packets.filter((p) => p.drop).length,
      blocked: 0,
    },
    dropsByProtocol: {},
  }
}

function descriptorsFromClassic(packets: readonly PacketEnvelope[]): PacketRecordDescriptor[] {
  return packets.map((pkt) => ({
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

describe('Step 10 — golden byte-identity corpus', () => {
  it('empty classic PCAP restores byte-for-byte', async () => {
    const header = writeClassicPcap({ header: classicHeader(), packets: [] })
    const original = new Uint8Array(header)
    const plan = snapshot({
      fileName: 'empty.pcap',
      format: CaptureFormat.ClassicPcap,
      level: 'diagnostic',
      packets: [],
      descriptors: [],
    })
    const exported = await runIncrementalExport({
      plan,
      descriptors: [],
      sourceBlob: new Blob([header]),
    })
    const anonymized = concatChunks(exported.chunks)
    const recovery = await writeRecovery({
      source: original,
      descriptors: [],
      plan,
      anonymized,
    })
    const restored = await restoreOriginalFromDataFrames({
      recoveryBytes: recovery,
      anonymizedSha256: sha256(anonymized),
    })
    expect(restored.ok).toBe(true)
    if (!restored.ok) return
    expect(firstDifferingOffset(restored.value.original, original)).toBeNull()
    expect(bytesToHex(restored.value.originalSha256)).toBe(bytesToHex(sha256(original)))
  })

  it('diagnostic classic PCAP: recovery-on/off anonymized hashes match and restore equals original', async () => {
    const pkts = [
      envelope(1, payload(0x11), 24),
      envelope(2, payload(0x22), 24 + 16 + 32),
    ]
    const buffer = writeClassicPcap({ header: classicHeader(), packets: pkts })
    const original = new Uint8Array(buffer)
    const descriptors = descriptorsFromClassic(pkts)
    const packets = descriptors.map((d, i) =>
      planPacket(i, d, i === 0 ? { patches: [{ offset: 0, data: new Uint8Array([0xee]) }] } : undefined),
    )
    const plan = snapshot({
      fileName: 'diag.pcap',
      format: CaptureFormat.ClassicPcap,
      level: 'diagnostic',
      packets,
      descriptors,
    })
    const sourceBlob = new Blob([buffer])
    const off = await runIncrementalExport({ plan, descriptors, sourceBlob })
    const on = await runIncrementalExport({
      plan,
      descriptors,
      sourceBlob,
      provenance: new AnonymizedProvenanceRecorder(),
    })
    const anonOff = concatChunks(off.chunks)
    const anonOn = concatChunks(on.chunks)
    expect(bytesToHex(sha256(anonOn))).toBe(bytesToHex(sha256(anonOff)))

    const recovery = await writeRecovery({
      source: original,
      descriptors,
      plan,
      anonymized: anonOn,
    })
    const restored = await restoreOriginalFromDataFrames({
      recoveryBytes: recovery,
      anonymizedSha256: sha256(anonOn),
    })
    expect(restored.ok).toBe(true)
    if (!restored.ok) return
    expect(restored.value.original.byteLength).toBe(original.byteLength)
    expect(firstDifferingOffset(restored.value.original, original)).toBeNull()
  })

  it('high-privacy drop restores the original including dropped records', async () => {
    const pkts = [
      envelope(1, payload(0x31), 24),
      envelope(2, payload(0x32), 24 + 16 + 32),
      envelope(3, payload(0x33), 24 + 2 * (16 + 32)),
    ]
    const buffer = writeClassicPcap({ header: classicHeader(), packets: pkts })
    const original = new Uint8Array(buffer)
    const descriptors = descriptorsFromClassic(pkts)
    const packets = descriptors.map((d, i) => planPacket(i, d, i === 1 ? { drop: true } : undefined))
    const plan = snapshot({
      fileName: 'hp.pcap',
      format: CaptureFormat.ClassicPcap,
      level: 'high-privacy',
      packets,
      descriptors,
    })
    const exported = await runIncrementalExport({
      plan,
      descriptors,
      sourceBlob: new Blob([buffer]),
    })
    const anonymized = concatChunks(exported.chunks)
    expect(anonymized.byteLength).toBeLessThan(original.byteLength)

    const recovery = await writeRecovery({
      source: original,
      descriptors,
      plan,
      anonymized,
    })
    const restored = await restoreOriginalFromDataFrames({
      recoveryBytes: recovery,
      anonymizedSha256: sha256(anonymized),
    })
    expect(restored.ok).toBe(true)
    if (!restored.ok) return
    expect(bytesEqual(restored.value.original, original)).toBe(true)
  })

  it('PCAPNG diagnostic restore is byte-identical to the original file', async () => {
    const pkt = envelope(1, payload(0x44), 0)
    const sections = [{
      sectionIndex: 0,
      endian: Endian.Little,
      versionMajor: 1,
      versionMinor: 0,
      sectionLength: -1n,
    }]
    const interfaces = [{
      interfaceId: 0,
      sectionIndex: 0,
      linkType: 1,
      snapLen: 65535,
      tsResol: TimestampResolution.Microseconds,
      tsResolValue: 6,
      tsOffset: 0n,
    }]
    const buffer = writePcapng({ sections, interfaces, packets: [pkt] })
    const original = new Uint8Array(buffer)
    const descriptors: PacketRecordDescriptor[] = [{
      packetNumber: 1,
      timestamp: pkt.timestamp,
      capturedLength: pkt.capturedLength,
      originalLength: pkt.originalLength,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 0,
      dataOffset: 0,
    }]
    const packets = [planPacket(0, descriptors[0]!)]
    const plan = snapshot({
      fileName: 'diag.pcapng',
      format: CaptureFormat.Pcapng,
      level: 'diagnostic',
      packets,
      descriptors,
    })
    const exported = await runIncrementalExport({
      plan,
      descriptors,
      sourceBlob: new Blob([buffer]),
    })
    const anonymized = concatChunks(exported.chunks)
    const recovery = await writeRecovery({
      source: original,
      descriptors,
      plan,
      anonymized,
    })
    const restored = await restoreOriginalFromDataFrames({
      recoveryBytes: recovery,
      anonymizedSha256: sha256(anonymized),
    })
    expect(restored.ok).toBe(true)
    if (!restored.ok) return
    expect(firstDifferingOffset(restored.value.original, original)).toBeNull()
  })

  it('classic big-endian and nanosecond captures restore byte-for-byte', async () => {
    const cases = [
      { name: 'be.pcap', header: classicHeader({ endian: Endian.Big }) },
      {
        name: 'nano.pcap',
        header: classicHeader({ timestampResolution: TimestampResolution.Nanoseconds }),
      },
    ] as const
    for (const c of cases) {
      const nano = c.header.timestampResolution === TimestampResolution.Nanoseconds
      const stamp = nano
        ? { ticks: 1_700_000_000n * 1_000_000_000n, unitsPerSecond: 1_000_000_000n, offsetSeconds: 0n }
        : ts(1)
      const pkt: PacketEnvelope = {
        ...envelope(1, payload(0x55), 24),
        timestamp: stamp,
      }
      const buffer = writeClassicPcap({ header: c.header, packets: [pkt] })
      const original = new Uint8Array(buffer)
      const descriptors = descriptorsFromClassic([pkt])
      const packets = [planPacket(0, descriptors[0]!)]
      const plan = snapshot({
        fileName: c.name,
        format: CaptureFormat.ClassicPcap,
        level: 'diagnostic',
        packets,
        descriptors,
        classic: c.header,
      })
      const exported = await runIncrementalExport({
        plan,
        descriptors,
        sourceBlob: new Blob([buffer]),
      })
      const anonymized = concatChunks(exported.chunks)
      const recovery = await writeRecovery({ source: original, descriptors, plan, anonymized })
      const restored = await restoreOriginalFromDataFrames({
        recoveryBytes: recovery,
        anonymizedSha256: sha256(anonymized),
      })
      expect(restored.ok, c.name).toBe(true)
      if (!restored.ok) return
      expect(firstDifferingOffset(restored.value.original, original)).toBeNull()
    }
  })

  it('high-privacy truncated packet still restores the full original record', async () => {
    const pkt = envelope(1, payload(0x61, 48), 24)
    const buffer = writeClassicPcap({ header: classicHeader(), packets: [pkt] })
    const original = new Uint8Array(buffer)
    const descriptors = descriptorsFromClassic([pkt])
    const packets = [planPacket(0, descriptors[0]!, { truncatedLength: 16 })]
    const plan = snapshot({
      fileName: 'trunc.pcap',
      format: CaptureFormat.ClassicPcap,
      level: 'high-privacy',
      packets,
      descriptors,
    })
    const exported = await runIncrementalExport({
      plan,
      descriptors,
      sourceBlob: new Blob([buffer]),
    })
    const anonymized = concatChunks(exported.chunks)
    expect(anonymized.byteLength).toBeLessThan(original.byteLength)
    const recovery = await writeRecovery({ source: original, descriptors, plan, anonymized })
    const restored = await restoreOriginalFromDataFrames({
      recoveryBytes: recovery,
      anonymizedSha256: sha256(anonymized),
    })
    expect(restored.ok).toBe(true)
    if (!restored.ok) return
    expect(bytesEqual(restored.value.original, original)).toBe(true)
  })

  it('PCAPNG with two sections and trailing extra bytes restores the original file', async () => {
    const pkt0 = { ...envelope(1, payload(0x71), 0), sectionIndex: 0, interfaceId: 0 }
    const pkt1 = { ...envelope(2, payload(0x72), 0), sectionIndex: 1, interfaceId: 1 }
    const sections = [
      { sectionIndex: 0, endian: Endian.Little, versionMajor: 1, versionMinor: 0, sectionLength: -1n },
      { sectionIndex: 1, endian: Endian.Little, versionMajor: 1, versionMinor: 0, sectionLength: -1n },
    ]
    const interfaces = [
      {
        interfaceId: 0,
        sectionIndex: 0,
        linkType: 1,
        snapLen: 65535,
        tsResol: TimestampResolution.Microseconds,
        tsResolValue: 6,
        tsOffset: 0n,
      },
      {
        interfaceId: 1,
        sectionIndex: 1,
        linkType: 1,
        snapLen: 65535,
        tsResol: TimestampResolution.Microseconds,
        tsResolValue: 6,
        tsOffset: 0n,
      },
    ]
    const core = new Uint8Array(writePcapng({ sections, interfaces, packets: [pkt0, pkt1] }))
    const trailing = new Uint8Array([0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 16])
    const original = new Uint8Array(core.byteLength + trailing.byteLength)
    original.set(core)
    original.set(trailing, core.byteLength)
    const descriptors: PacketRecordDescriptor[] = [
      {
        packetNumber: 1,
        timestamp: pkt0.timestamp,
        capturedLength: pkt0.capturedLength,
        originalLength: pkt0.originalLength,
        linkType: 1,
        interfaceId: 0,
        sectionIndex: 0,
        fileOffset: 0,
        dataOffset: 0,
      },
      {
        packetNumber: 2,
        timestamp: pkt1.timestamp,
        capturedLength: pkt1.capturedLength,
        originalLength: pkt1.originalLength,
        linkType: 1,
        interfaceId: 1,
        sectionIndex: 1,
        fileOffset: Math.floor(core.byteLength / 2),
        dataOffset: Math.floor(core.byteLength / 2),
      },
    ]
    const packets = descriptors.map((d, i) => planPacket(i, d))
    const plan = snapshot({
      fileName: 'multi.pcapng',
      format: CaptureFormat.Pcapng,
      level: 'diagnostic',
      packets,
      descriptors,
      pcapngSections: sections,
      pcapngInterfaces: interfaces,
    })
    const exported = await runIncrementalExport({
      plan,
      descriptors,
      sourceBlob: new Blob([original]),
    })
    const anonymized = concatChunks(exported.chunks)
    const recovery = await writeRecovery({ source: original, descriptors, plan, anonymized })
    const restored = await restoreOriginalFromDataFrames({
      recoveryBytes: recovery,
      anonymizedSha256: sha256(anonymized),
    })
    expect(restored.ok).toBe(true)
    if (!restored.ok) return
    expect(firstDifferingOffset(restored.value.original, original)).toBeNull()
  })

  it('COPY_ANON stays opt-in in the release limits table', () => {
    expect(PCAP_RECOVERY_LIMITS.copyAnonDefaultEnabled).toBe(false)
  })
})
