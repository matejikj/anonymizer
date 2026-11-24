/**
 * Optional real-corpus probe (T46).
 * Never depends on agent scratch temp dirs or a fixed user path.
 * Set ANONYMIZER_LOCAL_CORPUS to a directory with hi2/obc2 samples to exercise locally.
 *
 * @vitest-environment node
 */
import { describe, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { readClassicPcap } from '../../src/pcap/capture/pcapReader'
import { runExportPipeline } from '../pcap/helpers/diagnosticPipeline'
import { analyze } from '../../src/engine/analyze'

const DIR = process.env.ANONYMIZER_LOCAL_CORPUS?.trim() || ''
const enabled = DIR.length > 0 && existsSync(DIR)

describe.skipIf(!enabled)('optional local corpus (ANONYMIZER_LOCAL_CORPUS)', () => {
  it('hi2 sip pcap both levels', () => {
    const name = 'hi2-20261012-001-sip.pcap'
    const path = join(DIR, name)
    if (!existsSync(path)) return
    const buf = readFileSync(path)
    const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
    const read = readClassicPcap(ab)
    const packets = (read as { packets?: unknown[] }).packets ?? []
    for (const level of ['diagnostic', 'high-privacy'] as const) {
      runExportPipeline(packets as never, level, name, `local-${name}-${level}`)
    }
  })

  it('obc2 pcap + log when present', () => {
    const pcapPath = join(DIR, 'obc2.pcap')
    if (existsSync(pcapPath)) {
      const buf = readFileSync(pcapPath)
      const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)
      const read = readClassicPcap(ab)
      const packets = (read as { packets?: unknown[] }).packets ?? []
      runExportPipeline(packets as never, 'diagnostic', 'obc2.pcap', 'local-obc2-diagnostic')
    }
    const logPath = join(DIR, 'obc2.log')
    if (existsSync(logPath)) {
      analyze(readFileSync(logPath, 'utf8'))
    }
  })
})
