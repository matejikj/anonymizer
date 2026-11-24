/**
 * T13 — file loading + report write for protocol census (shared by CLI and unit tests).
 */

import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { Blob } from 'node:buffer'
import { gunzipSync } from 'node:zlib'
import type { PacketEnvelope } from '../../../src/pcap/domain/types.ts'
import { CaptureFormat } from '../../../src/pcap/domain/types.ts'
import { probeFormat } from '../../../src/pcap/capture/probe.ts'
import { readCaptureIncremental } from '../../../src/pcap/capture/incrementalCaptureReader.ts'
import {
  detectCompressedFormat,
  stripGzipExtension,
} from '../../../src/correlation/import/decompressInput.ts'
import { MAX_PCAP_FILE_BYTES } from '../../../src/domain/capabilityContract.ts'
import {
  accumulateCaptureCensus,
  assertCensusReportHasNoLeaks,
  extractLeakSeedsFromPackets,
  finalizeCensusReport,
  formatCensusMarkdown,
  type ProtocolCensusReport,
} from './protocolCensusLib.ts'
import { voipCorpusScenarios, VOIP_SEED_TOKENS } from '../fixtures/voipCorpus.ts'

export function safeCensusLabel(filePath: string): string {
  return stripGzipExtension(basename(filePath)).replace(/[^\w.-]+/g, '_') || 'capture'
}

export function collectCensusInputs(args: string[]): string[] {
  const files: string[] = []
  for (const raw of args) {
    const p = resolve(raw)
    if (!existsSync(p)) continue
    const st = statSync(p)
    if (st.isDirectory()) {
      for (const name of readdirSync(p)) {
        if (/\.(pcap|pcapng)(\.gz)?$/i.test(name)) files.push(join(p, name))
      }
    } else {
      files.push(p)
    }
  }
  return files
}

export async function loadCensusPackets(filePath: string): Promise<{
  packets: PacketEnvelope[]
  label: string
}> {
  const label = safeCensusLabel(filePath)
  const raw = readFileSync(filePath)
  if (raw.byteLength === 0) throw new Error('empty-file')

  const head = new Uint8Array(raw.buffer, raw.byteOffset, Math.min(16, raw.byteLength))
  const compressed = detectCompressedFormat(head)
  let bytes: Uint8Array = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength)
  if (compressed === 'gzip') {
    // Node bench path: sync inflate with hard ceiling (product UI still uses DecompressionStream).
    const inflated = gunzipSync(raw)
    if (inflated.byteLength > MAX_PCAP_FILE_BYTES) throw new Error('gzip-bomb')
    bytes = new Uint8Array(inflated.buffer, inflated.byteOffset, inflated.byteLength)
  } else if (compressed) {
    throw new Error(`unsupported-compression:${compressed}`)
  }
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  const headAb = copy.buffer.slice(0, Math.min(8, copy.byteLength))
  const probed = probeFormat(headAb)
  // CaptureFormat.ClassicPcap === 0 — must not use truthiness.
  if (probed.format === null) throw new Error(probed.reason || 'unknown-format')

  const format = probed.format
  const blob = new Blob([copy])
  try {
    const read = await readCaptureIncremental(blob, format)
    return { packets: [...read.packets], label }
  } catch (err) {
    const detail = err instanceof Error ? `${err.name}:${err.message || 'empty'}` : String(err)
    throw new Error(`read-failed:${detail}`)
  }
}

export interface RunProtocolCensusOptions {
  readonly paths?: readonly string[]
  readonly includeSynthetic?: boolean
  readonly outDir: string
  readonly writeStamp?: boolean
}

export async function runProtocolCensus(options: RunProtocolCensusOptions): Promise<{
  readonly report: ProtocolCensusReport
  readonly jsonPath: string
  readonly mdPath: string
  readonly json: string
  readonly md: string
}> {
  const paths = options.paths ?? []
  const includeSynthetic = options.includeSynthetic ?? paths.length === 0
  const aggs = new Map()
  const labels: string[] = []
  const notes: string[] = []
  const allSeeds: string[] = []

  if (includeSynthetic) {
    notes.push(
      paths.length === 0
        ? 'No paths given — synthetic voipCorpus only.'
        : 'Including synthetic voipCorpus.',
    )
    for (const scenario of voipCorpusScenarios()) {
      const label = `synthetic-${scenario.id}`
      accumulateCaptureCensus(scenario.packets, label, aggs)
      labels.push(label)
    }
    allSeeds.push(...VOIP_SEED_TOKENS)
  }

  for (const filePath of collectCensusInputs([...paths])) {
    try {
      const { packets, label } = await loadCensusPackets(filePath)
      accumulateCaptureCensus(packets, label, aggs)
      labels.push(label)
      allSeeds.push(...extractLeakSeedsFromPackets(packets))
    } catch (err) {
      const msg =
        err instanceof Error
          ? err.message || err.name || 'error'
          : typeof err === 'string'
            ? err
            : 'error'
      notes.push(`Failed capture ${safeCensusLabel(filePath)}: ${msg}`)
    }
  }

  const report = finalizeCensusReport(aggs, labels, notes)
  const json = JSON.stringify(report, null, 2)
  const md = formatCensusMarkdown(report)
  assertCensusReportHasNoLeaks(json, md, allSeeds)

  mkdirSync(options.outDir, { recursive: true })
  const latestJson = join(options.outDir, 'protocol-census-latest.json')
  const latestMd = join(options.outDir, 'protocol-census-latest.md')
  writeFileSync(latestJson, json)
  writeFileSync(latestMd, md)
  if (options.writeStamp !== false) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    writeFileSync(join(options.outDir, `protocol-census-${stamp}.json`), json)
    writeFileSync(join(options.outDir, `protocol-census-${stamp}.md`), md)
  }

  return { report, jsonPath: latestJson, mdPath: latestMd, json, md }
}
