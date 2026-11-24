/**
 * Step 10 — no network/persistence in recovery paths; lock wipes secrets; reports stay clean.
 */

import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { CaptureFormat } from '../../src/pcap/domain/types'
import { PCAP_ENGINE_VERSION, hashPcapLevel, type PcapPlanSnapshot } from '../../src/pcap/export/planSnapshot'
import { emptyPlanChangeCounts } from '../../src/pcap/plan/planDisposition'
import { emptyChecksumCounts } from '../../src/pcap/checksums/types'
import { assertReportHasNoOriginalIdentifiers, buildExportReport } from '../../src/pcap/export/report'
import { RecoverySession } from '../../src/pcap/recovery/restore/recoverySession'
import { PCAP_RECOVERY_LIMITS } from '../../src/pcap/recovery/domain/limits'

const root = join(dirname(fileURLToPath(import.meta.url)), '../..')

function walkTs(dir: string): string[] {
  const out: string[] = []
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name)
    if (ent.isDirectory()) out.push(...walkTs(p))
    else if (ent.name.endsWith('.ts') || ent.name.endsWith('.tsx')) out.push(p)
  }
  return out
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
}

function minimalPlan(): PcapPlanSnapshot {
  return {
    generationId: 'gen-lifecycle',
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

describe('Step 10 — recovery lifecycle / zero network / no persistence', () => {
  it('recovery and recovery-UI modules never call network or IndexedDB APIs', () => {
    const dirs = [
      join(root, 'src/pcap/recovery'),
      join(root, 'src/features/pcap-recovery'),
    ]
    const forbidden = [
      { name: 'fetch(', re: /\bfetch\s*\(/ },
      { name: 'XMLHttpRequest', re: /\bXMLHttpRequest\b/ },
      { name: 'WebSocket', re: /\bWebSocket\b/ },
      { name: 'indexedDB', re: /\bindexedDB\b/ },
      { name: 'openRndLogAnonymizerDb', re: /\bopenRndLogAnonymizerDb\b/ },
      { name: 'localStorage', re: /\blocalStorage\b/ },
      { name: 'sessionStorage', re: /\bsessionStorage\b/ },
    ]
    for (const dir of dirs) {
      expect(statSync(dir).isDirectory()).toBe(true)
      for (const file of walkTs(dir)) {
        const src = stripComments(readFileSync(file, 'utf8'))
        for (const rule of forbidden) {
          expect(src, `${file} must not use ${rule.name}`).not.toMatch(rule.re)
        }
      }
    }
  })

  it('lock wipes index, cache, blobs and session id', () => {
    const session = new RecoverySession()
    session.beginGeneration('gen-wipe')
    session.anonymizedBlob = new Blob([new Uint8Array([1])])
    session.recoveryBlob = new Blob([new Uint8Array([2])])
    session.lock()
    expect(session.currentState).toBe('terminated')
    expect(session.currentSessionId).toBeNull()
    expect(session.lookup).toBeNull()
    expect(session.recoveryManifest).toBeNull()
    expect(session.decryptedFrameCache).toBeNull()
    expect(session.anonymizedBlob).toBeNull()
    expect(session.recoveryBlob).toBeNull()
    expect(session.anonymizedSha256).toBeNull()
  })

  it('export report may flag recoveryCreated but never passphrase, recoveryId, or hashes', () => {
    const report = buildExportReport({
      plan: minimalPlan(),
      exportedFileName: 'capture.anonymized.pcap',
      changedPackets: 1,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: {
        valid: true,
        exportValidation: { valid: true, packetCount: 1, issues: [] },
        exportIssues: [],
        newBlockingIssues: [],
        preservedBaselineIssues: [],
        validationValid: true,
        validationIssueCount: 0,
      },
      recoveryCreated: true,
    })
    const json = JSON.stringify(report)
    expect(report.recoveryCreated).toBe(true)
    expect(() => assertReportHasNoOriginalIdentifiers(json)).not.toThrow()
    expect(json).not.toContain(PCAP_RECOVERY_LIMITS.fileExtension.slice(1))
  })
})
