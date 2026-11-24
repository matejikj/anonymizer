/**
 * Krok 10 product-path performance bench (Node).
 *
 * - Detection: `analyze()` wall-clock baseline for all §11.2 profiles
 * - Export: chunked transform must match reference and meet §11.3 export budgets
 * Usage: npm run bench:text-pipeline
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { analyze } from '../../src/engine/analyze.ts'
import {
  generateProfile,
  PROFILE_SPECS,
  type ProfileKind,
} from './profileGenerator.ts'
import { toTransferableBuffers } from '../../src/engine/packedMatchIndex.ts'
import { transformWithPlan } from '../../src/engine/transform.ts'
import {
  applyPackedLineEndings,
  packLineEndingsFromText,
} from '../../src/features/export-log/lineEndings.ts'
import {
  exportAnonymizedChunkedMain,
  planExportChunks,
} from '../../src/features/export-log/exportCoordinator.ts'
import {
  buildSessionModel,
  clearSessionModel,
} from '../../src/features/workspace/sessionModel.ts'
import { getExportPlanSnapshot } from '../../src/features/export-log/replacementSnapshot.ts'

const here = path.dirname(fileURLToPath(import.meta.url))
const outDir = path.join(here, 'results')

/** Absolute §11.3 detect budgets — recorded; often exceeded for full detector suite. */
const DETECT_GATES = {
  common: 3_000,
  maximum: 12_000,
  'match-stress': 12_000,
  'long-line-stress': 12_000,
} as const

const EXPORT_GATES = {
  common: 2_000,
  maximum: 8_000,
  'match-stress': 8_000,
  'long-line-stress': 8_000,
} as const

type Row = {
  kind: ProfileKind
  lines: number
  utf8Mb: number
  matches: number
  detectMs: number
  exportMs: number
  chunkCount: number
  detectWithinGate: boolean
  exportOk: boolean
  exportMatchesReference: boolean
}

function runKind(kind: ProfileKind): Row {
  console.log(`\n=== ${kind} ===`)
  const genT0 = performance.now()
  const profile = generateProfile(PROFILE_SPECS[kind])
  console.log(
    `generated in ${(performance.now() - genT0).toFixed(0)}ms — lines=${profile.lineCount} utf8MB=${(profile.utf8ByteLength / (1024 * 1024)).toFixed(1)}`,
  )

  const detT0 = performance.now()
  const result = analyze(profile.text)
  const detectMs = performance.now() - detT0
  console.log(`detect ${detectMs.toFixed(0)}ms — matches=${result.matches.length}`)

  clearSessionModel()
  const lineEndings = packLineEndingsFromText(profile.text)
  const { buffers } = toTransferableBuffers(result.packed)
  buildSessionModel({
    text: profile.text.replace(/\r\n/g, '\n').replace(/\r/g, '\n'),
    detection: {
      requestId: 'text-pipeline',
      packedMatches: buffers,
      entities: result.entitySummaries,
      lineCount: result.lineCount,
      failedRuleIds: [],
    },
    fileName: `${kind}.log`,
    byteLength: profile.utf8ByteLength,
    mode: profile.utf8ByteLength > 30 * 1024 * 1024 ? 'large' : 'common',
    workerPlanTrusted: false,
    lineEndings,
  })

  const snap = getExportPlanSnapshot()!
  const maxChunkChars = snap.original.length > 2_000_000 ? 1_500_000 : 200_000
  const expT0 = performance.now()
  const chunked = exportAnonymizedChunkedMain(snap, maxChunkChars)
  const exportMs = performance.now() - expT0
  const reference = applyPackedLineEndings(
    transformWithPlan(snap.original, snap.packed, snap.plan),
    snap.lineEndings,
  )
  const exportMatchesReference = chunked === reference
  const chunkCount = planExportChunks(snap.original, maxChunkChars).length
  console.log(
    `export ${exportMs.toFixed(0)}ms — chunks=${chunkCount} parity=${exportMatchesReference}`,
  )

  const row: Row = {
    kind,
    lines: result.lineCount,
    utf8Mb: profile.utf8ByteLength / (1024 * 1024),
    matches: result.matches.length,
    detectMs,
    exportMs,
    chunkCount,
    detectWithinGate: detectMs <= DETECT_GATES[kind],
    exportOk: exportMs <= EXPORT_GATES[kind],
    exportMatchesReference,
  }
  clearSessionModel()
  return row
}

function main(): void {
  fs.mkdirSync(outDir, { recursive: true })
  const kinds = Object.keys(PROFILE_SPECS) as ProfileKind[]
  const rows: Row[] = []
  for (const kind of kinds) {
    rows.push(runKind(kind))
  }

  const exportOk = rows.every((r) => r.exportOk && r.exportMatchesReference)
  const detectOk = rows.every((r) => r.detectWithinGate)
  const decision = !exportOk ? 'NO-GO' : detectOk ? 'GO' : 'GO_WITH_CONSTRAINTS'

  const report = {
    generatedAt: new Date().toISOString(),
    decision,
    detectGates: DETECT_GATES,
    exportGates: EXPORT_GATES,
    rows,
    constraints: detectOk
      ? []
      : [
          'Full detector suite wall-clock exceeds absolute §11.3 detect budgets on this runner for one or more §11.2 profiles.',
          'Dual-pane load/scroll/heap for 90MB remain GO_WITH_CONSTRAINTS per tests/performance/BASELINE-REPORT.md (precomputed matches + decorations).',
          'Chunked export meets §11.3 export budgets with byte-identical parity to reference transform.',
          'Do not claim “detect common in ≤3s / maximum in ≤12s” until detection is optimized; view/export of 90MB is supported.',
        ],
  }
  const outPath = path.join(outDir, 'text-pipeline-bench.json')
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2))

  const md = [
    '# Krok 10 — product performance report',
    '',
    `Generated: ${report.generatedAt}`,
    '',
    `## Decision: **${decision}**`,
    '',
    ...(report.constraints.length
      ? ['### Constraints', ...report.constraints.map((c) => `- ${c}`), '']
      : []),
    '## Results',
    '',
    '| Profile | Lines | UTF-8 MiB | Matches | Detect ms | Detect OK | Export ms | Export OK | Parity |',
    '|---|---:|---:|---:|---:|:---:|---:|:---:|:---:|',
    ...rows.map(
      (r) =>
        `| ${r.kind} | ${r.lines} | ${r.utf8Mb.toFixed(1)} | ${r.matches} | ${r.detectMs.toFixed(0)} | ${r.detectWithinGate} | ${r.exportMs.toFixed(0)} | ${r.exportOk} | ${r.exportMatchesReference} |`,
    ),
    '',
    '## Related',
    '',
    '- Spike dual-pane / scroll / heap: `tests/performance/BASELINE-REPORT.md`',
    '- Worker chunk sizing: `tests/performance/detection-worker-bench results`',
    '',
  ].join('\n')
  fs.writeFileSync(path.join(here, 'TEXT-PIPELINE-REPORT.md'), md)

  console.log(`\nWrote ${outPath}`)
  console.log(`Wrote ${path.join(here, 'TEXT-PIPELINE-REPORT.md')}`)
  console.log(`Decision: ${decision}`)
  if (!exportOk) process.exitCode = 1
}

main()
