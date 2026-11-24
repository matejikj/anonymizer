import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { assertNever } from '../../src/domain/assertNever.ts'
import { sourceKindLabel, SourceKind } from '../../src/domain/sourceArtifact.ts'
import { profileImpactBlocksExport, ProfileImpactKind } from '../../src/pcap/profile/profileImpact.ts'
import { transformationIntentKindLabel } from '../../src/pcap/discovery/intentKind.ts'
import { isWorkerIssueCode, WorkerIssueCode } from '../../src/domain/issueCodes.ts'

const root = join(fileURLToPath(new URL('../..', import.meta.url)))

function runArchitectureCheck(): { ok: boolean; output: string } {
  try {
    const output = execSync('node scripts/check-architecture.mjs', {
      cwd: root,
      encoding: 'utf8',
    })
    return { ok: true, output }
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; message?: string }
    return { ok: false, output: [e.stdout, e.stderr, e.message].filter(Boolean).join('\n') }
  }
}

describe('Stage 16 — architecture enforcement', () => {
  it('check:architecture passes on clean tree', () => {
    const result = runArchitectureCheck()
    expect(result.ok, result.output).toBe(true)
    expect(result.output).toContain('check-architecture: OK')
  })

  it('assertNever throws on unexpected union member', () => {
    expect(() => assertNever('unexpected' as never)).toThrow(/Unexpected value/)
  })

  it('SourceKind exhaustiveness', () => {
    expect(sourceKindLabel(SourceKind.Text)).toBe('text')
    expect(sourceKindLabel(SourceKind.Pcap)).toBe('pcap')
  })

  it('TransformationIntent exhaustiveness', () => {
    expect(transformationIntentKindLabel('entity-replacement')).toBe('entity-replacement')
    expect(transformationIntentKindLabel('drop-record')).toBe('drop-record')
  })

  it('ProfileImpact classifier blocks export for discovery/representation-policy', () => {
    expect(
      profileImpactBlocksExport({ kind: ProfileImpactKind.Discovery, reasonKey: 'rules-changed' }),
    ).toBe(true)
    expect(
      profileImpactBlocksExport({ kind: ProfileImpactKind.ExportOnly, reasonKey: 'export-only' }),
    ).toBe(false)
  })

  it('worker issue codes are stable strings', () => {
    expect(isWorkerIssueCode(WorkerIssueCode.Cancelled)).toBe(true)
    expect(isWorkerIssueCode('not-a-code')).toBe(false)
  })

  it('worker protocol files declare version constants', () => {
    const protocol = readFileSync(join(root, 'src/workers/protocol.ts'), 'utf8')
    expect(protocol).toContain('DETECTION_PROTOCOL_VERSION')
    expect(protocol).toContain('EXPORT_PROTOCOL_VERSION')
    expect(protocol).toContain('validateDetectionProtocolVersion')
  })

  it('processing worker protocol has typed wire DTOs', () => {
    const wp = readFileSync(join(root, 'src/pcap/processing/workerProtocol.ts'), 'utf8')
    expect(wp).toContain('WireCoverageEntry')
    expect(wp).not.toMatch(/coverage:\s*unknown\[\]/)
  })

  it('pcap export cancel/chunk-ack carry protocolVersion', () => {
    const wp = readFileSync(join(root, 'src/pcap/export/workerProtocol.ts'), 'utf8')
    expect(wp).toMatch(/type:\s*'cancel'.*protocolVersion/s)
    expect(wp).toMatch(/type:\s*'chunk-ack'.*protocolVersion/s)
  })

  it('perf diagnostics live in production src tree', () => {
    const src = readFileSync(join(root, 'src/diagnostics/perfDiagnostics.ts'), 'utf8')
    expect(src).toContain('getActivePerfDiagnostics')
    expect(src).toContain('recordTransfer')
    expect(src).not.toMatch(/console\.(log|info|debug)\([^)]*filename/i)
  })
})

describe('Stage 16 — guard failure detection (synthetic)', () => {
  it('architecture script detects file.arrayBuffer in PCAP load path pattern', () => {
    const snippet = 'await file.arrayBuffer()'
    expect(/\bfile\.arrayBuffer\s*\(\s*\)/.test(snippet)).toBe(true)
    const allowed = 'await file.slice(0, 64).arrayBuffer()'
    expect(/\bfile\.arrayBuffer\s*\(\s*\)/.test(allowed)).toBe(false)
  })

  it('architecture script detects inline preset pattern', () => {
    const bad = "preset: 'safe'"
    expect(/\bpreset\s*:\s*['"]safe['"]/.test(bad)).toBe(true)
  })
})
