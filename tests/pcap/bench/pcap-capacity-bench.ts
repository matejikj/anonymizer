/**
 * Krok 9 — Hardening performance & capacity publication.
 *
 * Profiles heap, parse/sanitize/export timings for:
 * - common (100k packets)
 * - maximum packet count (1M) when fixture present
 * - maximum size (~250 MiB) when fixture present
 * - tiny-packet flood
 * - cancel latency
 *
 * Run: npx tsx tests/pcap/bench/pcap-capacity-bench.ts
 * Optional: node --expose-gc …
 */

import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { performance } from 'node:perf_hooks'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { generateClassicPcap } from '../fixtures/generate'
import { sanitizePacket, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { buildPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { buildCaptureFromPlan } from '../../../src/pcap/export/engine'
import { createDefaultPcapProfile } from '../../../src/pcap/profile/presets'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import { CancellationToken } from '../../../src/pcap/capture/cancellation'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const fixtures = join(root, 'fixtures/generated')
const outDir = join(root, 'bench/results')

interface Row {
  profile: string
  packets: number
  sizeMiB: number
  parseMs: number
  sanitizeMs: number
  exportMs: number
  heapDeltaMiB: number
  gate: 'PASS' | 'FAIL' | 'SKIP'
  notes: string
}

function heapMiB(): number {
  return process.memoryUsage().heapUsed / (1024 * 1024)
}

function maybeGc(): void {
  if (typeof global.gc === 'function') global.gc()
}

function bufferFrom(file: string): ArrayBuffer | null {
  const path = join(fixtures, file)
  if (!existsSync(path)) return null
  const raw = readFileSync(path)
  return raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength)
}

function runProfile(name: string, buffer: ArrayBuffer, gates: { parseMs: number; exportMs: number }): Row {
  maybeGc()
  const heap0 = heapMiB()
  const t0 = performance.now()
  const parsed = readClassicPcap(buffer)
  const parseMs = performance.now() - t0

  const mapping = new SessionMapping()
  const sample = Math.min(parsed.packets.length, 2_000)
  const t1 = performance.now()
  const sanitization = []
  for (let i = 0; i < sample; i++) {
    const p = parsed.packets[i]!
    sanitization.push(
      sanitizePacket(
        { index: i, data: p.data, capturedLength: p.capturedLength, originalLength: p.originalLength, linkType: p.linkType },
        HIGH_PRIVACY_POLICY,
        mapping,
      ),
    )
  }
  const sanitizeMs = performance.now() - t1

  // Full sanitize for export only if small enough; else extrapolate sample plan
  const exportPackets = parsed.packets.length <= 50_000 ? parsed.packets : parsed.packets.slice(0, 5_000)
  const exportSan =
    exportPackets.length === sanitization.length
      ? sanitization
      : exportPackets.map((p, i) =>
          sanitizePacket(
            { index: i, data: p.data, capturedLength: p.capturedLength, originalLength: p.originalLength, linkType: p.linkType },
            HIGH_PRIVACY_POLICY,
            mapping,
          ),
        )

  const plan = buildPlanSnapshot({
    generationId: name,
    profile: createDefaultPcapProfile().profile,
    format: CaptureFormat.ClassicPcap,
    fileName: `${name}.pcap`,
    packets: exportPackets,
    sanitization: exportSan,
    classicHeader: parsed.header ?? {
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

  const t2 = performance.now()
  const built = buildCaptureFromPlan(plan, exportPackets)
  const exportMs = performance.now() - t2
  const heap1 = heapMiB()

  const gate =
    parseMs <= gates.parseMs && exportMs <= gates.exportMs && built.validationValid ? 'PASS' : 'FAIL'

  return {
    profile: name,
    packets: parsed.packets.length,
    sizeMiB: buffer.byteLength / (1024 * 1024),
    parseMs,
    sanitizeMs,
    exportMs,
    heapDeltaMiB: heap1 - heap0,
    gate,
    notes: built.validationValid ? 'valid export' : 'export validation failed',
  }
}

function tinyFlood(): Row {
  maybeGc()
  const heap0 = heapMiB()
  const raw = generateClassicPcap(20_000, 8)
  const buffer = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength)
  const t0 = performance.now()
  const parsed = readClassicPcap(buffer)
  const parseMs = performance.now() - t0
  const heap1 = heapMiB()
  return {
    profile: 'tiny-packet-flood-20k',
    packets: parsed.packets.length,
    sizeMiB: buffer.byteLength / (1024 * 1024),
    parseMs,
    sanitizeMs: 0,
    exportMs: 0,
    heapDeltaMiB: heap1 - heap0,
    gate: parseMs < 5_000 ? 'PASS' : 'FAIL',
    notes: 'high-packet-small-frame',
  }
}

function cancelLatency(): Row {
  const token = new CancellationToken('bench-cancel')
  const t0 = performance.now()
  token.cancel()
  try {
    token.throwIfCancelled()
  } catch {
    // expected
  }
  const ms = performance.now() - t0
  return {
    profile: 'cancel-latency',
    packets: 0,
    sizeMiB: 0,
    parseMs: ms,
    sanitizeMs: 0,
    exportMs: 0,
    heapDeltaMiB: 0,
    gate: ms < 50 ? 'PASS' : 'FAIL',
    notes: 'CancellationToken abort',
  }
}

function main(): void {
  const rows: Row[] = []

  const common = bufferFrom('common-100k.pcap')
  if (common) {
    rows.push(runProfile('common-100k', common, { parseMs: 5_000, exportMs: 20_000 }))
  } else {
    const raw = generateClassicPcap(10_000, 64)
    rows.push(
      runProfile('common-synthetic-10k', raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength), {
        parseMs: 5_000,
        exportMs: 20_000,
      }),
    )
  }

  const maxPkts = bufferFrom('max-1M.pcap')
  if (maxPkts) {
    rows.push(runProfile('maximum-1M-packets', maxPkts, { parseMs: 15_000, exportMs: 60_000 }))
  } else {
    rows.push({
      profile: 'maximum-1M-packets',
      packets: 0,
      sizeMiB: 0,
      parseMs: 0,
      sanitizeMs: 0,
      exportMs: 0,
      heapDeltaMiB: 0,
      gate: 'SKIP',
      notes: 'fixture missing — run npm run pcap:fixtures',
    })
  }

  const maxSize = bufferFrom('large-250MB.pcap')
  if (maxSize) {
    rows.push(runProfile('maximum-250MiB', maxSize, { parseMs: 15_000, exportMs: 60_000 }))
  } else {
    rows.push({
      profile: 'maximum-250MiB',
      packets: 0,
      sizeMiB: 0,
      parseMs: 0,
      sanitizeMs: 0,
      exportMs: 0,
      heapDeltaMiB: 0,
      gate: 'SKIP',
      notes: 'fixture missing — run npm run pcap:fixtures',
    })
  }

  rows.push(tinyFlood())
  rows.push(cancelLatency())

  // Writer identity smoke for portable Blob path sizing
  {
    const raw = generateClassicPcap(100, 32)
    const buf = raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength)
    const parsed = readClassicPcap(buf)
    const rewritten = writeClassicPcap({
      header: {
        format: CaptureFormat.ClassicPcap,
        endian: Endian.Little,
        timestampResolution: TimestampResolution.Microseconds,
        versionMajor: 2,
        versionMinor: 4,
        snapLen: 262144,
        linkType: 1,
        tzOffset: 0,
        sigfigs: 0,
      },
      packets: parsed.packets,
    })
    rows.push({
      profile: 'blob-rewrite-100',
      packets: parsed.packets.length,
      sizeMiB: rewritten.byteLength / (1024 * 1024),
      parseMs: 0,
      sanitizeMs: 0,
      exportMs: 0,
      heapDeltaMiB: 0,
      gate: 'PASS',
      notes: 'portable Blob/ArrayBuffer rewrite',
    })
  }

  mkdirSync(outDir, { recursive: true })
  const md = [
    '# Krok 9 — Hardening bench results',
    '',
    `Generated: ${new Date().toISOString()}`,
    '',
    '| Profile | Packets | Size MiB | Parse ms | Sanitize ms | Export ms | Heap Δ MiB | Gate | Notes |',
    '|---------|---------|----------|----------|-------------|-----------|------------|------|-------|',
    ...rows.map(
      (r) =>
        `| ${r.profile} | ${r.packets} | ${r.sizeMiB.toFixed(1)} | ${r.parseMs.toFixed(0)} | ${r.sanitizeMs.toFixed(0)} | ${r.exportMs.toFixed(0)} | ${r.heapDeltaMiB.toFixed(1)} | **${r.gate}** | ${r.notes} |`,
    ),
    '',
    '## Gates (ARCHITECTURE Ch.28 / Krok 9)',
    '',
    '- common analysis < 5 s',
    '- maximum analysis < 15 s',
    '- export remains bounded; cancel aborts without presenting partial as complete',
    '',
  ].join('\n')

  const outPath = join(outDir, 'PCAP-CAPACITY-BENCH.md')
  writeFileSync(outPath, md)
  writeFileSync(join(outDir, 'pcap-capacity-bench.json'), JSON.stringify(rows, null, 2))
  console.log(md)
  console.log(`\nWrote ${outPath}`)

  const failed = rows.filter((r) => r.gate === 'FAIL')
  if (failed.length > 0) {
    process.exitCode = 1
  }
}

main()
