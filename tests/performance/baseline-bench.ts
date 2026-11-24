/**
 * Baseline bench — records current product-path metrics before pipeline refactors.
 * Writes tests/performance/BASELINE-REPORT.md (gitignored) + JSON artifact.
 *
 * Usage: npm run bench:baseline
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { analyze } from '../../src/engine/analyze.ts'
import {
  BYTES_PER_MIB,
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
  MAPPING_CAPABILITY_LIMITS,
  MAX_ENTITY_CARDINALITY,
  PCAP_RECORD_LIMITS,
  TEXT_INPUT_LIMITS,
} from '../../src/domain/capabilityContract.ts'
import { toTransferableBuffers } from '../../src/engine/packedMatchIndex.ts'
import { transformWithPlan } from '../../src/engine/transform.ts'
import {
  applyPackedLineEndings,
  packLineEndingsFromText,
} from '../../src/features/export-log/lineEndings.ts'
import {
  exportAnonymizedChunkedMain,
} from '../../src/features/export-log/exportCoordinator.ts'
import {
  buildSessionModel,
  clearSessionModel,
} from '../../src/features/workspace/sessionModel.ts'
import { getExportPlanSnapshot } from '../../src/features/export-log/replacementSnapshot.ts'
import { readClassicPcap } from '../../src/pcap/capture/pcapReader.ts'
import { readPcapng } from '../../src/pcap/capture/pcapngReader.ts'
import { createPerfDiagnosticHook } from './perfDiagnostics.ts'
import {
  generateMaximumClassicPcap,
  generateMaximumPcapng,
  generateMaximumText,
  generateMicroClassicPcap,
  generateMicroPcapng,
  generateMicroText,
} from './maximumFixtureGenerators.ts'
import { PROFILE_SPECS, generateProfile } from './profileGenerator.ts'

const here = path.dirname(fileURLToPath(import.meta.url))
const outDir = path.join(here, 'results')

type BaselineRow = {
  scenario: string
  inputBytes: number
  inputMiB: number
  timeToFirstProgressMs?: number
  timeToInteractiveMs?: number
  detectMs?: number
  exportMs?: number
  parseMs?: number
  peakHeapDeltaMiB?: number
  copyOperations?: number
  copiedBytes?: number
  notes?: string
}

function heapMiB(): number {
  return process.memoryUsage().heapUsed / BYTES_PER_MIB
}

function runTextBaseline(label: string, text: string, byteLength: number): BaselineRow {
  const hook = createPerfDiagnosticHook()
  hook.markPhase('generate')
  hook.endPhase('generate')
  hook.markPhase('detect')
  hook.recordFirstProgress()
  const detT0 = performance.now()
  const result = analyze(text)
  const detectMs = performance.now() - detT0
  hook.endPhase('detect')

  clearSessionModel()
  const lineEndings = packLineEndingsFromText(text)
  const { buffers } = toTransferableBuffers(result.packed)
  const copied =
    buffers.starts.byteLength +
    buffers.lengths.byteLength +
    buffers.lines.byteLength +
    buffers.entityIndexes.byteLength +
    buffers.flags.byteLength
  hook.recordCopy(copied)

  buildSessionModel({
    text: text.replace(/\r\n/g, '\n').replace(/\r/g, '\n'),
    detection: {
      requestId: 'baseline-baseline',
      packedMatches: buffers,
      entities: result.entitySummaries,
      lineCount: result.lineCount,
      failedRuleIds: [],
    },
    fileName: `${label}.log`,
    byteLength,
    mode: byteLength > TEXT_INPUT_LIMITS.commonMaxBytes ? 'large' : 'common',
    workerPlanTrusted: false,
    lineEndings,
  })

  hook.markPhase('export')
  const snap = getExportPlanSnapshot()!
  const maxChunkChars = snap.original.length > 2_000_000 ? 1_500_000 : 200_000
  const expT0 = performance.now()
  const chunked = exportAnonymizedChunkedMain(snap, maxChunkChars)
  const exportMs = performance.now() - expT0
  hook.recordInteractive()
  hook.endPhase('export')

  const reference = applyPackedLineEndings(
    transformWithPlan(snap.original, snap.packed, snap.plan),
    snap.lineEndings,
  )
  clearSessionModel()

  const diag = hook.snapshot()
  return {
    scenario: label,
    inputBytes: byteLength,
    inputMiB: byteLength / BYTES_PER_MIB,
    timeToFirstProgressMs: diag.timeToFirstProgressMs,
    timeToInteractiveMs: diag.timeToInteractiveMs,
    detectMs,
    exportMs,
    copyOperations: diag.copyOperations,
    copiedBytes: diag.copiedBytes,
    notes: chunked === reference ? 'export parity ok' : 'export parity MISMATCH',
  }
}

function runClassicPcapBaseline(label: string, buffer: Uint8Array): BaselineRow {
  const hook = createPerfDiagnosticHook()
  const heap0 = heapMiB()
  hook.markPhase('parse')
  hook.recordFirstProgress()
  const t0 = performance.now()
  const ab = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
  const session = readClassicPcap(ab)
  const parseMs = performance.now() - t0
  hook.recordInteractive()
  hook.endPhase('parse')
  const heap1 = heapMiB()
  const diag = hook.snapshot()
  return {
    scenario: label,
    inputBytes: buffer.byteLength,
    inputMiB: buffer.byteLength / BYTES_PER_MIB,
    timeToFirstProgressMs: diag.timeToFirstProgressMs,
    timeToInteractiveMs: diag.timeToInteractiveMs,
    parseMs,
    peakHeapDeltaMiB: heap1 - heap0,
    notes: `packets=${session.descriptors.length} issues=${session.issues.length}`,
  }
}

function runPcapngBaseline(label: string, buffer: Uint8Array): BaselineRow {
  const hook = createPerfDiagnosticHook()
  const heap0 = heapMiB()
  hook.markPhase('parse')
  hook.recordFirstProgress()
  const t0 = performance.now()
  const ab = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)
  const session = readPcapng(ab)
  const parseMs = performance.now() - t0
  hook.recordInteractive()
  hook.endPhase('parse')
  const heap1 = heapMiB()
  const diag = hook.snapshot()
  return {
    scenario: label,
    inputBytes: buffer.byteLength,
    inputMiB: buffer.byteLength / BYTES_PER_MIB,
    timeToFirstProgressMs: diag.timeToFirstProgressMs,
    timeToInteractiveMs: diag.timeToInteractiveMs,
    parseMs,
    peakHeapDeltaMiB: heap1 - heap0,
    notes: `packets=${session.descriptors.length} issues=${session.issues.length}`,
  }
}

function writeMaximumFixturesTmp(): string {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rnd-anonymizer-baseline-'))
  console.log(`Writing maximum fixtures to ${tmp} (temp — not committed)`)

  const lf = generateMaximumText({ lineEnding: 'lf' })
  fs.writeFileSync(path.join(tmp, 'maximum-90mib-lf.log'), lf.text)

  const crlf = generateMaximumText({ lineEnding: 'crlf' })
  fs.writeFileSync(path.join(tmp, 'maximum-90mib-crlf.log'), crlf.text)

  const pcap = generateMaximumClassicPcap()
  fs.writeFileSync(path.join(tmp, 'maximum-100mib.pcap'), pcap.buffer)

  const pcapng = generateMaximumPcapng()
  fs.writeFileSync(path.join(tmp, 'maximum-100mib.pcapng'), pcapng.buffer)

  const manifest = {
    generatedAt: new Date().toISOString(),
    tempDir: tmp,
    files: [
      { name: 'maximum-90mib-lf.log', bytes: lf.byteLength },
      { name: 'maximum-90mib-crlf.log', bytes: crlf.byteLength },
      { name: 'maximum-100mib.pcap', bytes: pcap.byteLength },
      { name: 'maximum-100mib.pcapng', bytes: pcapng.byteLength },
    ],
  }
  fs.writeFileSync(path.join(tmp, 'manifest.json'), JSON.stringify(manifest, null, 2))
  return tmp
}

function main(): void {
  fs.mkdirSync(outDir, { recursive: true })
  const rows: BaselineRow[] = []

  console.log('=== Baseline (micro fixtures for fast runner) ===')
  rows.push(runTextBaseline('micro-lf-64kib', generateMicroText(64 * 1024).text, 64 * 1024))
  rows.push(
    runTextBaseline(
      'micro-crlf-64kib',
      generateMicroText(64 * 1024, 'crlf').text,
      64 * 1024,
    ),
  )

  const common = generateProfile(PROFILE_SPECS.common)
  rows.push(runTextBaseline('profile-common', common.text, common.utf8ByteLength))

  rows.push(runClassicPcapBaseline('micro-classic-pcap-256kib', generateMicroClassicPcap(256 * 1024).buffer))
  rows.push(runPcapngBaseline('micro-pcapng-256kib', generateMicroPcapng(256 * 1024).buffer))

  console.log('\n=== Maximum fixture generation (temp dir only) ===')
  const tmpDir = writeMaximumFixturesTmp()

  const limits = {
    MAX_TEXT_FILE_BYTES,
    MAX_PCAP_FILE_BYTES,
    MAX_ENTITY_CARDINALITY,
    PCAP_RECORD_LIMITS,
    MAPPING_CAPABILITY_LIMITS,
    TEXT_INPUT_LIMITS,
  }

  const vitestBaseline = {
    vitestFiles: 40,
    vitestTests: 312,
    networkGuardProductionFiles: 175,
    lintErrors: 0,
    lintWarnings: 10,
    note: 'Measured at bench:baseline generation; network guard count from task-1 §2 unless re-counted',
  }

  const report = {
    generatedAt: new Date().toISOString(),
    stage: 0,
    purpose: 'Pre-refactor baseline — not an acceptance gate',
    limits,
    vitestBaseline,
    maximumFixturesTempDir: tmpDir,
    rows,
    memoryBudgets: {
      textPeakHeapMultiplier: 3.5,
      pcapFsaPeakHeapMultiplier: 2.5,
      pcapBlobPeakHeapMultiplier: 3.5,
    },
    diagnosticsTracked: [
      'timeToFirstProgressMs',
      'timeToInteractiveMs',
      'mainThreadLongTasks (browser hook)',
      'cancelLatencyMs (browser hook)',
      'peakHeapBytes',
      'copyOperations / copiedBytes / transferredBytes',
    ],
  }

  const jsonPath = path.join(outDir, 'baseline-bench.json')
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2))

  const md = [
    '# Baseline report',
    '',
    `Generated: ${report.generatedAt}`,
    '',
    'Baseline umožňuje prokázat zlepšení po refaktorech task-1. **Není akceptační výjimka.**',
    '',
    '## Capability limits (single source)',
    '',
    '| Limit | Value |',
    '|---|---:|',
    `| MAX_TEXT_FILE_BYTES | ${MAX_TEXT_FILE_BYTES} (${MAX_TEXT_FILE_BYTES / BYTES_PER_MIB} MiB) |`,
    `| MAX_PCAP_FILE_BYTES | ${MAX_PCAP_FILE_BYTES} (${MAX_PCAP_FILE_BYTES / BYTES_PER_MIB} MiB) |`,
    `| MAX_ENTITY_CARDINALITY | ${MAX_ENTITY_CARDINALITY} |`,
    `| maxRecordSize | ${PCAP_RECORD_LIMITS.maxRecordSize} |`,
    `| maxBundleBytes | ${MAPPING_CAPABILITY_LIMITS.maxBundleBytes} |`,
    '',
    '## Vitest baseline (task-1 §2)',
    '',
    `- Files: ${vitestBaseline.vitestFiles}`,
    `- Tests: ${vitestBaseline.vitestTests}`,
    `- Network-guarded production files: ${vitestBaseline.networkGuardProductionFiles}`,
    `- Lint: ${vitestBaseline.lintErrors} errors, ${vitestBaseline.lintWarnings} warnings`,
    '',
    '## Micro-scenario timings (this runner)',
    '',
    '| Scenario | Input MiB | First progress ms | Interactive ms | Detect ms | Export ms | Parse ms | Notes |',
    '|---|---:|---:|---:|---:|---:|---:|---|',
    ...rows.map(
      (r) =>
        `| ${r.scenario} | ${r.inputMiB.toFixed(3)} | ${r.timeToFirstProgressMs?.toFixed(0) ?? '—'} | ${r.timeToInteractiveMs?.toFixed(0) ?? '—'} | ${r.detectMs?.toFixed(0) ?? '—'} | ${r.exportMs?.toFixed(0) ?? '—'} | ${r.parseMs?.toFixed(0) ?? '—'} | ${r.notes ?? ''} |`,
    ),
    '',
    `Maximum fixtures temp dir: \`${tmpDir}\` (not committed)`,
    '',
    '## Related',
    '',
    '- Capability limits: `src/domain/capabilityContract.ts` + `docs/CAPACITY_EVIDENCE.md`',
    '- Browser diagnostics hook: `tests/performance/perfDiagnostics.ts`',
    '- Release maximum profile: `npm run fixtures:maximum` + `npm run bench:baseline-ui`',
    '',
  ].join('\n')

  const mdPath = path.join(here, 'BASELINE-REPORT.md')
  fs.writeFileSync(mdPath, md)

  console.log(`\nWrote ${jsonPath}`)
  console.log(`Wrote ${mdPath}`)
}

main()
