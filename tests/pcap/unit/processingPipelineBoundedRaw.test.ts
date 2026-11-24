/**
 * R04 / V11 — processCapture must not retain the whole capture against the raw buffer budget.
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import { PCAP_KERNEL_BUDGETS } from '../../../src/domain/capabilityContract'
import { processCapture } from '../../../src/pcap/processing/processingPipeline'
import { policyFromPreset } from '../../../src/pcap/sanitize/engine'
import { generateClassicPcap } from '../fixtures/generate'

describe('processingPipeline bounded raw buffers (R04)', () => {
  it('processes ~68 MiB synthetic classic PCAP under the 100 MiB file cap without raw-buffers-exceeded', async () => {
    const buf = generateClassicPcap(1100, 65000)
    expect(buf.byteLength).toBeGreaterThan(PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes)
    expect(buf.byteLength).toBeLessThan(100 * 1024 * 1024)

    const session = await processCapture({
      blob: new Blob([buf]),
      fileName: 'large-synthetic.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('diagnostic'),
      generationId: 'r04-gen',
      sourceId: 'r04-src',
    })

    expect(session.descriptors.length).toBe(1100)
    expect(session.discovery.totalPackets).toBe(1100)
    expect(session.discovery.packetDiscovery.length).toBe(1100)
    expect(session.packets).toBeUndefined()
    expect(session.budgetSnapshot.peakRawBytes).toBeLessThanOrEqual(
      PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes,
    )
  })
})
