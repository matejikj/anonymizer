/**
 * Step 1 — PCAP recovery integration contract after two-preset refactor.
 */

import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  PCAP_ENGINE_VERSION,
  hashPcapLevel,
  type PcapPlanSnapshot,
} from '../../src/pcap/export/planSnapshot'
import { planToWireExport, planFromWire } from '../../src/pcap/processing/planWireAdapter'
import {
  PCAP_RECOVERY_ERROR,
  PCAP_RECOVERY_ERROR_CODES,
  PCAP_RECOVERY_LIMITS,
  assertPlanIdentity,
  assertRecoveryExportAllowed,
  buildEmptyDataFrameHeaderVector,
  buildPreambleLayoutVector,
  bytesToHex,
  canTransitionRecoverySession,
  isRecoveryExportEnabled,
  isRecoverySupportedForLevel,
  normalizeRecoveryExportOptions,
  planIdentityFromSnapshot,
  RECOVERY_FORMAT_VECTOR_EMPTY,
  RECOVERY_FRAME_HEADER_BYTES,
  RECOVERY_FRAME_TYPE_DATA,
  RECOVERY_MAGIC_ASCII,
  RECOVERY_PREAMBLE_LENGTH,
  PCAP_RECOVERY_PROTOCOL_VERSION,
  toWireRecoveryExportOptions,
  validateRecoveryProtocolVersion,
} from '../../src/pcap/recovery'
import { CaptureFormat } from '../../src/pcap/domain/types'
import { emptyPlanChangeCounts } from '../../src/pcap/plan/planDisposition'

const root = join(dirname(fileURLToPath(import.meta.url)), '../..')
const srcDir = join(root, 'src')
const recoveryDir = join(srcDir, 'pcap/recovery')

function walkTsFiles(dir: string): string[] {
  const out: string[] = []
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name)
    if (ent.isDirectory()) out.push(...walkTsFiles(p))
    else if (ent.name.endsWith('.ts') || ent.name.endsWith('.tsx')) out.push(p)
  }
  return out
}

function minimalPlan(level: 'diagnostic' | 'high-privacy'): PcapPlanSnapshot {
  return {
    generationId: 'gen-recovery-1',
    pcapLevel: level,
    profileId: `pcap-${level}`,
    profileHash: hashPcapLevel(level),
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

describe('Step 1 — PCAP recovery integration contract', () => {
  it('binds plan identity to pcapLevel + policyHash + generationId for both levels', () => {
    for (const level of ['diagnostic', 'high-privacy'] as const) {
      const plan = minimalPlan(level)
      const identity = planIdentityFromSnapshot(plan)
      expect(identity).toEqual({
        generationId: 'gen-recovery-1',
        pcapLevel: level,
        policyHash: plan.profileHash,
        engineVersion: PCAP_ENGINE_VERSION,
      })
      expect(assertPlanIdentity(plan).ok).toBe(true)
      expect(isRecoverySupportedForLevel(level)).toBe(true)
      const allowed = assertRecoveryExportAllowed(plan, { enabled: true })
      expect(allowed.ok).toBe(true)
    }
  })

  it('disabled recovery normalizes to a no-op option and clears wire payload', () => {
    expect(normalizeRecoveryExportOptions(undefined)).toEqual({ enabled: false })
    expect(normalizeRecoveryExportOptions({ enabled: false })).toEqual({ enabled: false })
    expect(isRecoveryExportEnabled(undefined)).toBe(false)
    expect(toWireRecoveryExportOptions(undefined)).toBeUndefined()
    expect(toWireRecoveryExportOptions({ enabled: false })).toBeUndefined()
    expect(toWireRecoveryExportOptions({ enabled: true })?.copyAnon).toBeUndefined()
    expect(toWireRecoveryExportOptions({ enabled: true, copyAnon: true })?.copyAnon).toBe(true)
  })

  it('wire plan round-trip preserves pcapLevel and policyHash alias', () => {
    const plan = minimalPlan('high-privacy')
    const { wire } = planToWireExport(plan)
    expect(wire.pcapLevel).toBe('high-privacy')
    expect(wire.policyHash).toBe(plan.profileHash)
    expect(wire.profileHash).toBe(plan.profileHash)
    const restored = planFromWire(wire, wire.profileId)
    expect(restored.pcapLevel).toBe('high-privacy')
    expect(restored.profileHash).toBe(plan.profileHash)
    expect(planIdentityFromSnapshot(restored).policyHash).toBe(plan.profileHash)
  })

  it('defines stable error codes and shared limits used by writer/reader', () => {
    expect(PCAP_RECOVERY_ERROR_CODES).toContain(PCAP_RECOVERY_ERROR.authFailed)
    expect(PCAP_RECOVERY_ERROR_CODES).toContain(PCAP_RECOVERY_ERROR.pairMismatch)
    expect(PCAP_RECOVERY_LIMITS.fileExtension).toBe('.rnd-pcap-recovery.bin')
    expect(PCAP_RECOVERY_LIMITS.maxFramePlaintextBytes).toBe(2 * 1024 * 1024)
    expect(PCAP_RECOVERY_LIMITS.defaultFramePlaintextBytes).toBe(1 * 1024 * 1024)
    expect(PCAP_RECOVERY_LIMITS.maxUnackedChunks).toBe(2)
    expect(PCAP_RECOVERY_LIMITS.sessionIdleTimeoutMs).toBe(15 * 60 * 1000)
    expect(PCAP_RECOVERY_LIMITS.copyAnonDefaultEnabled).toBe(false)
    expect(PCAP_RECOVERY_LIMITS.copyAnonMinRunBytes).toBe(16)
  })

  it('versioned recovery protocol rejects mismatched versions', () => {
    expect(validateRecoveryProtocolVersion(PCAP_RECOVERY_PROTOCOL_VERSION)).toBeNull()
    expect(validateRecoveryProtocolVersion(PCAP_RECOVERY_PROTOCOL_VERSION + 1)).toBe(
      'invalid-recovery-protocol-version',
    )
  })

  it('session FSM allows unlocked → searching → unlocked and rejects idle → unlocked', () => {
    expect(canTransitionRecoverySession('unlocked', 'searching')).toBe(true)
    expect(canTransitionRecoverySession('searching', 'unlocked')).toBe(true)
    expect(canTransitionRecoverySession('idle', 'unlocked')).toBe(false)
  })

  it('v4 preamble layout vector matches canonical offsets', () => {
    const preamble = buildPreambleLayoutVector()
    expect(preamble.byteLength).toBe(RECOVERY_PREAMBLE_LENGTH)
    expect(RECOVERY_FORMAT_VECTOR_EMPTY.magicAscii).toBe(RECOVERY_MAGIC_ASCII)
    expect(bytesToHex(preamble.subarray(0, 8))).toBe(bytesToHex(new TextEncoder().encode('RNDPCAPR')))
    const view = new DataView(preamble.buffer)
    expect(view.getUint16(8, true)).toBe(4)
    expect(view.getUint16(10, true)).toBe(4)
    expect(view.getUint16(12, true)).toBe(RECOVERY_PREAMBLE_LENGTH)
    expect(view.getUint16(18, true)).toBe(0)

    const frameHdr = buildEmptyDataFrameHeaderVector(0)
    expect(frameHdr.byteLength).toBe(RECOVERY_FRAME_HEADER_BYTES)
    expect(frameHdr[0]).toBe(RECOVERY_FRAME_TYPE_DATA)
    expect(new DataView(frameHdr.buffer).getUint32(8, true)).toBe(0)
    expect(new DataView(frameHdr.buffer).getUint32(12, true)).toBe(0)
  })

  it('recovery modules do not import text profile schema or profile persistence', () => {
    const forbidden = [
      /domain\/configSchema/,
      /domain\/rulesetValidate/,
      /persistence\/profileRepository/,
      /persistence\/pcapProfileRepository/,
      /features\/profiles/,
      /pcap\/profile\/schema/,
    ]
    for (const file of walkTsFiles(recoveryDir)) {
      const src = readFileSync(file, 'utf8')
      for (const re of forbidden) {
        expect(src, file).not.toMatch(re)
      }
      expect(src, file).not.toMatch(/\bPcapProfile\b/)
      expect(src, file).not.toMatch(/\bprofileId\b/)
    }
  })

  it('disabled recovery keeps anonymized export hot path free of recovery runtime imports', () => {
    for (const rel of [
      'pcap/export/coordinator.ts',
      'pcap/export/incremental/incrementalExportEngine.ts',
    ]) {
      const src = readFileSync(join(srcDir, rel), 'utf8')
      expect(src).not.toMatch(/pcap\/recovery\/(export|restore)\//)
      expect(src).not.toMatch(/recoveryBundleWriter|dualExportCoordinator|compactIndexBuilder/)
    }
    // Worker may dynamic-import recovery writer only when recovery.enabled.
    const workerSrc = readFileSync(join(srcDir, 'workers/pcap-export.worker.ts'), 'utf8')
    expect(workerSrc).not.toMatch(
      /import\s+[^;]*from\s+['"][^'"]*pcap\/recovery\//,
    )
    expect(workerSrc).toMatch(/import\(\s*['"][^'"]*recovery\/export\/recoveryBundleWriter/)
  })
})
