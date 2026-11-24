/**
 * Max-size PCAPNG fixture must be structurally readable (SHB 28B, IDB opts, per-section if_id).
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat } from '../../src/pcap/domain/types'
import { processCapture } from '../../src/pcap/processing/processingPipeline'
import { policyFromPreset } from '../../src/pcap/sanitize/engine'
import { generateMaximumPcapng } from './maximumFixtureGenerators'

describe('maximumFixtureGenerators PCAPNG', () => {
  it('produces a readable multi-section PCAPNG under 2 MiB', async () => {
    const fix = generateMaximumPcapng({ targetBytes: 2 * 1024 * 1024 })
    expect(fix.packetCount).toBeGreaterThan(100)
    expect(fix.byteLength).toBeLessThanOrEqual(2 * 1024 * 1024)

    const session = await processCapture({
      blob: new Blob([fix.buffer]),
      fileName: 'fixture-ng.pcapng',
      format: CaptureFormat.Pcapng,
      policy: policyFromPreset('diagnostic'),
      generationId: 'fix-ng',
      sourceId: 'fix-ng',
    })

    expect(session.descriptors.length).toBe(fix.packetCount)
    expect(session.issues.filter((i) => i.code.startsWith('pcapng-'))).toEqual([])
  })
})
