/**
 * R04 — processCapture must not retain O(capture) raw copies against rawBuffersMaxBytes.
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import { PCAP_KERNEL_BUDGETS } from '../../../src/domain/capabilityContract'
import { processCapture } from '../../../src/pcap/processing/processingPipeline'
import { policyFromPreset } from '../../../src/pcap/sanitize/engine'
import { generateClassicPcap } from '../fixtures/generate'

describe('R04 streaming raw budget', () => {
  it('processes ~68 MiB synthetic classic PCAP without exceeding raw buffer cap', async () => {
    const buf = generateClassicPcap(1100, 65000)
    expect(buf.length).toBeGreaterThan(64 * 1024 * 1024)

    const session = await processCapture({
      blob: new Blob([buf]),
      fileName: 'r04.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('diagnostic'),
      generationId: 'g-r04',
      sourceId: 's-r04',
    })

    expect(session.descriptors.length).toBe(1100)
    expect(session.packets).toBeUndefined()
    expect(session.budgetSnapshot.peakRawBytes).toBeLessThanOrEqual(
      PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes,
    )
    expect(session.discovery.packetDiscovery.length).toBe(1100)
  })

  it('high packet-count classic PCAP stays under journalMaxBytes (no per-coverage facts)', async () => {
    // ~20k small UDP frames — formerly exhausted journal via addFact-per-coverage-row.
    const buf = generateClassicPcap(20_000, 200)
    const session = await processCapture({
      blob: new Blob([buf]),
      fileName: 'r04-journal.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('diagnostic'),
      generationId: 'g-r04-j',
      sourceId: 's-r04-j',
    })
    expect(session.descriptors.length).toBe(20_000)
    expect(session.budgetSnapshot.peakJournalBytes).toBeLessThanOrEqual(
      PCAP_KERNEL_BUDGETS.journalMaxBytes,
    )
    expect(session.journal.packets.length).toBe(20_000)
    expect(session.journal.facts.length).toBe(0)
  })
})
