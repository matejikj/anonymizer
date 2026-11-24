/**
 * Step 5 — DualExportCoordinator atomicity, streaming directory write, report flag.
 */

import { describe, expect, it, vi } from 'vitest'
import { DualExportCoordinator, recoverySidecarFileName } from '../../src/pcap/recovery/export/dualExportCoordinator'
import { BlobExportSink, writeBlobToSinkStreaming } from '../../src/pcap/export/sinks'
import { assertReportHasNoOriginalIdentifiers, buildExportReport } from '../../src/pcap/export/report'
import { CaptureFormat } from '../../src/pcap/domain/types'
import { PCAP_ENGINE_VERSION, hashPcapLevel, type PcapPlanSnapshot } from '../../src/pcap/export/planSnapshot'
import { emptyPlanChangeCounts } from '../../src/pcap/plan/planDisposition'
import { emptyChecksumCounts } from '../../src/pcap/checksums/types'
import { sha256, bytesToHex } from '../../src/crypto/incrementalSha256'
import { PCAP_RECOVERY_LIMITS } from '../../src/pcap/recovery/domain/limits'

function minimalPlan(): PcapPlanSnapshot {
  return {
    generationId: 'gen-step5',
    pcapLevel: 'diagnostic',
    profileId: 'pcap-diagnostic',
    profileHash: hashPcapLevel('diagnostic'),
    format: CaptureFormat.ClassicPcap,
    fileName: 'sample.pcap',
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

describe('Step 5 — DualExportCoordinator', () => {
  it('names recovery sidecar with the recovery extension', () => {
    expect(recoverySidecarFileName('a.anonymized.pcap')).toBe(
      `a.anonymized.pcap${PCAP_RECOVERY_LIMITS.fileExtension}`,
    )
  })

  it('finalizes a complete pair only when both sinks succeed', async () => {
    const dual = await DualExportCoordinator.open({
      generationId: 'g1',
      anonymizedFileName: 'out.anonymized.pcap',
      recoveryEnabled: true,
    })
    const anonChunk = new Uint8Array([1, 2, 3]).buffer
    const recChunk = new Uint8Array([9, 9]).buffer
    expect(await dual.writeAnonymized(anonChunk, 'g1')).toBe(true)
    expect(await dual.writeRecovery!(recChunk, 'g1')).toBe(true)
    const fin = await dual.finalize()
    expect(fin.recoveryCreated).toBe(true)
    expect(fin.anonymized.byteLength).toBe(3)
    expect(fin.recovery?.byteLength).toBe(2)
    expect(dual.pairComplete).toBe(true)
  })

  it('abort after partial write does not report a completed pair', async () => {
    const dual = await DualExportCoordinator.open({
      generationId: 'g2',
      anonymizedFileName: 'out.anonymized.pcap',
      recoveryEnabled: true,
    })
    await dual.writeAnonymized(new Uint8Array([1]).buffer, 'g2')
    await dual.abort()
    expect(dual.pairComplete).toBe(false)
    expect(dual.failed).toBe(true)
    await expect(dual.finalize()).rejects.toThrow()
  })

  it('anonymized bytes stay identical whether recovery sink is used', async () => {
    const payload = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01])
    const off = await DualExportCoordinator.open({
      generationId: 'hash-off',
      anonymizedFileName: 'out.anonymized.pcap',
      recoveryEnabled: false,
    })
    await off.writeAnonymized(payload.buffer.slice(0), 'hash-off')
    const finOff = await off.finalize()

    const on = await DualExportCoordinator.open({
      generationId: 'hash-on',
      anonymizedFileName: 'out.anonymized.pcap',
      recoveryEnabled: true,
    })
    await on.writeAnonymized(payload.buffer.slice(0), 'hash-on')
    await on.writeRecovery!(new Uint8Array([0xaa]).buffer, 'hash-on')
    const finOn = await on.finalize()

    const hashOff = bytesToHex(sha256(new Uint8Array(await finOff.anonymized.blob!.arrayBuffer())))
    const hashOn = bytesToHex(sha256(new Uint8Array(await finOn.anonymized.blob!.arrayBuffer())))
    expect(hashOn).toBe(hashOff)
    expect(finOff.recoveryCreated).toBe(false)
    expect(finOn.recoveryCreated).toBe(true)
  })
})

describe('Step 5 — streaming blob write', () => {
  it('writeBlobToSinkStreaming never calls blob.arrayBuffer()', async () => {
    const parts = [new Uint8Array([1, 2]), new Uint8Array([3, 4, 5])]
    const blob = new Blob(parts)
    const spy = vi.spyOn(Blob.prototype, 'arrayBuffer')
    const sink = new BlobExportSink('x.bin')
    await writeBlobToSinkStreaming(sink, blob)
    const fin = await sink.finalize()
    expect(fin.byteLength).toBe(5)
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  })
})

describe('Step 5 — report recoveryCreated only', () => {
  it('allows recoveryCreated boolean and rejects secrets/hashes', () => {
    const report = buildExportReport({
      plan: minimalPlan(),
      exportedFileName: 'ignored.pcap',
      changedPackets: 0,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: {
        valid: true,
        exportValidation: { valid: true, packetCount: 0, issues: [] },
        exportIssues: [],
        newBlockingIssues: [],
        preservedBaselineIssues: [],
        validationValid: true,
        validationIssueCount: 0,
      },
      recoveryCreated: true,
    })
    expect(report.recoveryCreated).toBe(true)
    expect(report.policyHash).toBeTruthy()
    const json = JSON.stringify(report)
    expect(() => assertReportHasNoOriginalIdentifiers(json)).not.toThrow()

    expect(() =>
      assertReportHasNoOriginalIdentifiers(
        JSON.stringify({ ...report, passphrase: 'secret' }),
      ),
    ).toThrow(/passphrase/)

    expect(() =>
      assertReportHasNoOriginalIdentifiers(
        JSON.stringify({
          ...report,
          anonymizedSha256: bytesToHex(sha256(new Uint8Array([1]))),
        }),
      ),
    ).toThrow(/sha256/)
  })
})
