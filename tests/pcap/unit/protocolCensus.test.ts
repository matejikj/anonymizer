/**
 * T13 — protocol census aggregation + leak-free report shape.
 */

import { describe, expect, it } from 'vitest'
import { writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync } from 'node:zlib'
import { fileURLToPath } from 'node:url'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter.ts'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types.ts'
import { voipCorpusScenarios, VOIP_SEED, VOIP_SEED_TOKENS } from '../fixtures/voipCorpus.ts'
import {
  accumulateCaptureCensus,
  assertCensusReportHasNoLeaks,
  finalizeCensusReport,
  formatCensusMarkdown,
} from '../bench/protocolCensusLib.ts'
import { runProtocolCensus } from '../bench/protocolCensusRunner.ts'

const root = join(fileURLToPath(new URL('../../..', import.meta.url)))
const outDir = join(root, 'tests/pcap/bench/results')

describe('protocol census (T13)', () => {
  it('aggregates synthetic voip corpus by family without original values', () => {
    const aggs = new Map()
    const labels: string[] = []
    for (const scenario of voipCorpusScenarios()) {
      const label = `syn-${scenario.id}`
      accumulateCaptureCensus(scenario.packets, label, aggs)
      labels.push(label)
    }
    const report = finalizeCensusReport(aggs, labels, ['synthetic-only'])
    expect(report.version).toBe(1)
    expect(report.captureCount).toBe(labels.length)
    expect(report.rows.length).toBeGreaterThan(0)

    const sip = report.rows.find((r) => r.key === 'family:sip')
    expect(sip).toBeDefined()
    expect(sip!.packets).toBeGreaterThan(0)

    const json = JSON.stringify(report)
    const md = formatCensusMarkdown(report)
    expect(json).not.toContain(VOIP_SEED.ip)
    expect(json).not.toContain(VOIP_SEED.hostname)
    expect(json).not.toContain(VOIP_SEED.callId)
    expect(json).not.toContain(VOIP_SEED.phone)
    expect(md).not.toContain(VOIP_SEED.ip)
    expect(md).not.toContain(VOIP_SEED.hostname)
    assertCensusReportHasNoLeaks(json, md, VOIP_SEED_TOKENS)

    expect(json).not.toMatch(/"key":\s*"port:\d+"/)
    expect(md).toMatch(/Unidentified transport/)
  })

  it('runner --synthetic writes leak-free latest report', async () => {
    const { report, json, md, jsonPath, mdPath } = await runProtocolCensus({
      includeSynthetic: true,
      paths: [],
      outDir,
      writeStamp: false,
    })
    expect(report.rows.length).toBeGreaterThan(0)
    expect(existsSync(jsonPath)).toBe(true)
    expect(existsSync(mdPath)).toBe(true)
    assertCensusReportHasNoLeaks(json, md, VOIP_SEED_TOKENS)
    expect(json).not.toContain(VOIP_SEED.icePwd)
  })

  it('reads gzip-wrapped classic PCAP', async () => {
    const scenario = voipCorpusScenarios()[0]!
    const header = {
      format: CaptureFormat.ClassicPcap as const,
      endian: Endian.Little,
      timestampResolution: TimestampResolution.Microseconds,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    }
    const ab = writeClassicPcap({ header, packets: scenario.packets })
    mkdirSync(outDir, { recursive: true })
    const gzPath = join(outDir, 't13-synthetic-sip.pcap.gz')
    writeFileSync(gzPath, gzipSync(Buffer.from(ab)))

    const { json, report } = await runProtocolCensus({
      paths: [gzPath],
      includeSynthetic: false,
      outDir,
      writeStamp: false,
    })
    expect(report.notes.join('; '), report.notes.join('; ')).not.toMatch(/Failed capture/)
    expect(report.captureLabels.some((l) => l.includes('t13-synthetic-sip'))).toBe(true)
    expect(json).not.toContain(VOIP_SEED.callId)
    expect(readFileSync(join(outDir, 'protocol-census-latest.json'), 'utf8')).toMatch(/t13-synthetic-sip/)
  })
})
