import { describe, it, expect } from 'vitest'
import { buildPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { buildCaptureFromPlan, chunkBuffer } from '../../../src/pcap/export/engine'
import { previewBytesFromPlan, buildExportEnvelope } from '../../../src/pcap/export/packetBuilder'
import { anonymizedPcapFileName } from '../../../src/pcap/export/fileName'
import { buildExportReport } from '../../../src/pcap/export/report'
import type { ExportValidationOutcome } from '../../../src/pcap/export/incremental/baselineCompare'
import { emptyChecksumCounts } from '../../../src/pcap/checksums/types'
import {
  runPcapExport,
  cancelPcapExport,
  PcapExportCancelledError,
} from '../../../src/pcap/export/coordinator'
import { createTestPcapSessionFromPackets } from './pcapSessionTestHelpers'
import { validateCaptureWithTshark } from '../helpers/externalValidation'
import { validateClassicPcap } from '../../../src/pcap/capture/validator'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { ClassicPcapHeader, PacketEnvelope } from '../../../src/pcap/domain/types'
import { createDefaultPcapProfile } from '../../../src/pcap/profile/presets'
import { sanitizePacket, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { TimestampMapping } from '../../../src/pcap/anonymization/timestampMapping'
import { locateLayers } from '../../../src/pcap/checksums/locate'

function mockValidation(valid = true): ExportValidationOutcome {
  return {
    valid,
    exportValidation: { valid, packetCount: 0, issues: [] },
    exportIssues: [],
    newBlockingIssues: [],
    preservedBaselineIssues: [],
    validationValid: valid,
    validationIssueCount: 0,
  }
}

function makeEthIpPacket(src: number[], dst: number[], n: number, payloadSize = 4): PacketEnvelope {
  const data = new Uint8Array(38 + payloadSize)
  data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data[16] = 0
  data[17] = 28 + payloadSize
  data[23] = 17
  data.set(src, 26)
  data.set(dst, 30)
  data[34] = 0
  data[35] = 53
  data[36] = 0
  data[37] = 80
  data[38] = 0
  data[39] = 8 + payloadSize
  return {
    packetNumber: n,
    timestamp: { ticks: BigInt(1700000000 + n) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

function checksumSkipOffsets(data: Uint8Array, linkType: number): Set<number> {
  const skip = new Set<number>()
  const layers = locateLayers(data, linkType, data.length)
  if (layers.l3Proto === 'ipv4') skip.add(layers.l3Offset + 10).add(layers.l3Offset + 11)
  if (layers.l4Proto === 'tcp') skip.add(layers.l4Offset + 16).add(layers.l4Offset + 17)
  if (layers.l4Proto === 'udp') skip.add(layers.l4Offset + 6).add(layers.l4Offset + 7)
  if (layers.l4Proto === 'icmpv4') skip.add(layers.l4Offset + 2).add(layers.l4Offset + 3)
  return skip
}

describe('PcapPlanSnapshot export parity', () => {
  it('preview patch bytes match export envelope except checksum fields', () => {
    const pkt = makeEthIpPacket([192, 168, 1, 10], [8, 8, 8, 8], 1)
    const mapping = new SessionMapping()
    const san = sanitizePacket(
      { index: 0, data: pkt.data, capturedLength: pkt.capturedLength, originalLength: pkt.originalLength, linkType: 1 },
      HIGH_PRIVACY_POLICY,
      mapping,
    )
    const plan = buildPlanSnapshot({
      generationId: '1',
      profile: createDefaultPcapProfile().profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'test.pcap',
      packets: [pkt],
      sanitization: [san],
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
    })

    const preview = previewBytesFromPlan(pkt, plan.packets[0]!)
    const { envelope } = buildExportEnvelope(pkt, plan.packets[0]!, new TimestampMapping(), true)
    const skip = checksumSkipOffsets(envelope.data, plan.packets[0]!.linkType)

    for (let i = 0; i < preview.length; i++) {
      if (skip.has(i)) continue
      expect(envelope.data[i]).toBe(preview[i])
    }
  })

  it('full export parity per packet against preview plan', () => {
    const packets = [
      makeEthIpPacket([192, 168, 10, 1], [8, 8, 4, 4], 1),
      makeEthIpPacket([192, 168, 10, 2], [1, 1, 1, 1], 2, 64),
    ]
    const mapping = new SessionMapping()
    const sanitization = packets.map((p, i) =>
      sanitizePacket(
        { index: i, data: p.data, capturedLength: p.capturedLength, originalLength: p.originalLength, linkType: 1 },
        HIGH_PRIVACY_POLICY,
        mapping,
      ),
    )
    const header: ClassicPcapHeader = {
      format: CaptureFormat.ClassicPcap,
      endian: Endian.Little,
      timestampResolution: TimestampResolution.Microseconds,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    }
    const plan = buildPlanSnapshot({
      generationId: 'parity-1',
      profile: createDefaultPcapProfile().profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'parity.pcap',
      packets,
      sanitization,
      classicHeader: header,
    })
    const built = buildCaptureFromPlan(plan, packets)
    const reread = readClassicPcap(built.buffer)

    for (let i = 0; i < packets.length; i++) {
      const preview = previewBytesFromPlan(packets[i]!, plan.packets[i]!)
      const exported = reread.packets[i]!.data
      const skip = checksumSkipOffsets(exported, plan.packets[i]!.linkType)
      expect(exported.length).toBe(preview.length)
      for (let b = 0; b < preview.length; b++) {
        if (skip.has(b)) continue
        expect(exported[b]).toBe(preview[b])
      }
    }
  })

  it('exports valid classic PCAP and re-parses', () => {
    const packets = [
      makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1),
      makeEthIpPacket([192, 168, 1, 2], [10, 0, 0, 2], 2),
    ]
    const mapping = new SessionMapping()
    const sanitization = packets.map((p, i) =>
      sanitizePacket(
        { index: i, data: p.data, capturedLength: p.capturedLength, originalLength: p.originalLength, linkType: 1 },
        HIGH_PRIVACY_POLICY,
        mapping,
      ),
    )
    const header: ClassicPcapHeader = {
      format: CaptureFormat.ClassicPcap,
      endian: Endian.Little,
      timestampResolution: TimestampResolution.Microseconds,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    }
    const plan = buildPlanSnapshot({
      generationId: 'exp-1',
      profile: createDefaultPcapProfile().profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'capture.pcap',
      packets,
      sanitization,
      classicHeader: header,
    })

    const built = buildCaptureFromPlan(plan, packets)
    expect(built.validationValid).toBe(true)
    expect(built.fileName).toBe('capture.anonymized.pcap')

    const validation = validateClassicPcap(built.buffer)
    expect(validation.valid).toBe(true)
    expect(validation.packetCount).toBe(2)

    const reread = readClassicPcap(built.buffer)
    expect(reread.packets.length).toBe(2)
    // Original IPs must not appear
    for (const p of reread.packets) {
      const str = Array.from(p.data).join(',')
      expect(str).not.toContain('192,168')
    }
  })

  it('report contains no original entity values', () => {
    const report = buildExportReport({
      plan: buildPlanSnapshot({
        generationId: '1',
        profile: createDefaultPcapProfile().profile,
        format: CaptureFormat.ClassicPcap,
        fileName: 'x.pcap',
        packets: [],
        sanitization: [],
      }),
      exportedFileName: 'x.anonymized.pcap',
      changedPackets: 1,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: mockValidation(),
    })
    const json = JSON.stringify(report)
    expect(json).not.toContain('192.168')
    expect(json).not.toMatch(/"originalValue"\s*:/)
    expect(json).not.toContain('password=secret')
    expect(report.format).toBe('rnd-log-anonymizer-pcap-report')
    expect(report.schemaVersion).toBe(8)
  })

  it('chunkBuffer splits for streaming sink', () => {
    const buf = new ArrayBuffer(600_000)
    const chunks = chunkBuffer(buf, 256 * 1024)
    expect(chunks.length).toBe(3)
    expect(chunks.reduce((s, c) => s + c.byteLength, 0)).toBe(600_000)
  })
})

describe('anonymizedPcapFileName', () => {
  it('names classic and pcapng captures', () => {
    expect(anonymizedPcapFileName('foo.pcap', 'pcap')).toBe('foo.anonymized.pcap')
    expect(anonymizedPcapFileName('bar.pcapng', 'pcapng')).toBe('bar.anonymized.pcapng')
  })
})

describe('runPcapExport cancel', () => {
  it('cancelled export rejects without treating as success', async () => {
    const packets = Array.from({ length: 200 }, (_, i) =>
      makeEthIpPacket([192, 168, 0, (i % 250) + 1], [10, 0, 0, (i % 250) + 1], i + 1, 512),
    )
    const session = await createTestPcapSessionFromPackets({ fileName: 'large.pcap', packets })

    const exportPromise = runPcapExport({
      plan: session.plan,
      descriptors: session.descriptors,
      sourceBlob: session.sourceFile,
      unsupportedLayers: 0,
      protocolCoverage: [],
      preferFileSystemAccess: false,
    })
    cancelPcapExport()
    await expect(exportPromise).rejects.toBeInstanceOf(PcapExportCancelledError)
  })
})

describe('external validation', () => {
  it('tshark/capinfos accepts exported capture when tool is available', async () => {
    const pkt = makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1)
    const mapping = new SessionMapping()
    const san = sanitizePacket(
      { index: 0, data: pkt.data, capturedLength: pkt.capturedLength, originalLength: pkt.originalLength, linkType: 1 },
      HIGH_PRIVACY_POLICY,
      mapping,
    )
    const plan = buildPlanSnapshot({
      generationId: 'ext-1',
      profile: createDefaultPcapProfile().profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'ext.pcap',
      packets: [pkt],
      sanitization: [san],
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
    })
    const built = buildCaptureFromPlan(plan, [pkt])
    const ext = await validateCaptureWithTshark(built.buffer, built.fileName)
    if (ext.available) {
      expect(ext.valid).toBe(true)
    }
  })
})
