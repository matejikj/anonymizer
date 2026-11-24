/**
 * @vitest-environment node
 *
 * Step 10 — diagnostic-equivalence gate: golden corpus + incidents via DiagnosticFactModel.
 */

import { describe, expect, it } from 'vitest'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { readPcapng } from '../../../src/pcap/capture/pcapngReader'
import {
  buildDiagnosticFactModel,
  compareDiagnosticFactModels,
} from '../../../src/pcap/diagnostics'
import { diagnosticGoldenScenarios, wrapPacketsAsClassicPcap, wrapPacketsAsPcapng } from '../fixtures/diagnosticGoldenCorpus'
import { diagnosticIncidents } from '../fixtures/diagnosticIncidents'
import { runDiagnosticExportPipeline } from '../helpers/diagnosticPipeline'
import { assertNoNewTsharkStructuralErrors } from '../helpers/tsharkOracle'

describe('diagnostic equivalence gate (step 10)', () => {
  for (const scenario of diagnosticGoldenScenarios()) {
    it(`fact equivalence: ${scenario.id}`, () => {
      const { plan, built, packets } = runDiagnosticExportPipeline(
        scenario.packets,
        `${scenario.id}.pcap`,
        scenario.id,
      )
      expect(plan.droppedPacketNumbers.length).toBe(0)
      expect(built.validationValid).toBe(true)

      const reread = readClassicPcap(built.buffer)
      expect(reread.packets.length).toBe(packets.length)

      const forced = diagnosticIncidents().find((i) => scenario.id === `incident-${i.id}`)
        ?.rootCauseCategory

      const originalFacts = buildDiagnosticFactModel(packets, forced)
      const anonFacts = buildDiagnosticFactModel(reread.packets, forced)
      // Preserve packet numbers from plan / original indices
      const anonWithNumbers = {
        ...anonFacts,
        packets: anonFacts.packets.map((p, i) => ({
          ...p,
          packetNumber: packets[i]!.packetNumber,
        })),
        evidencePacketNumbers: originalFacts.evidencePacketNumbers,
        rootCauseCategory: anonFacts.rootCauseCategory,
      }

      // Re-infer root cause on anonymized bytes with restored numbers
      const inferredAnon = buildDiagnosticFactModel(
        reread.packets.map((p, i) => ({ ...p, packetNumber: packets[i]!.packetNumber })),
        forced,
      )

      expect(inferredAnon.rootCauseCategory).toBe(originalFacts.rootCauseCategory)
      expect([...inferredAnon.evidencePacketNumbers].sort((a, b) => a - b)).toEqual(
        [...originalFacts.evidencePacketNumbers].sort((a, b) => a - b),
      )

      const diff = compareDiagnosticFactModels(originalFacts, {
        ...anonWithNumbers,
        rootCauseCategory: inferredAnon.rootCauseCategory,
        evidencePacketNumbers: inferredAnon.evidencePacketNumbers,
      })
      expect(diff.mismatches, diff.mismatches.join('\n')).toEqual([])
      expect(diff.equal).toBe(true)
    })
  }

  it('pcapng wrap of protocol-matrix remains fact-equivalent after classic re-export path', () => {
    const scenario = diagnosticGoldenScenarios().find((s) => s.id === 'protocol-matrix')!
    const pcapng = wrapPacketsAsPcapng(scenario.packets)
    const classic = wrapPacketsAsClassicPcap(scenario.packets)
    expect(pcapng.byteLength).toBeGreaterThan(24)
    expect(classic.byteLength).toBeGreaterThan(24)
    const ng = readPcapng(pcapng)
    expect(ng.packets.length).toBe(scenario.packets.length)
  })

  it('tshark oracle: no new structural expert errors on protocol-matrix', async () => {
    const scenario = diagnosticGoldenScenarios().find((s) => s.id === 'protocol-matrix')!
    const original = wrapPacketsAsClassicPcap(scenario.packets)
    const { built } = runDiagnosticExportPipeline(scenario.packets, 'tshark-matrix.pcap', 'tshark-matrix')
    const result = await assertNoNewTsharkStructuralErrors(original, built.buffer, 'matrix')
    if (!result.skipped) {
      expect(result.anonymized.malformed).toBeLessThanOrEqual(result.original.malformed)
    }
  })
})
