/**
 * @vitest-environment node
 *
 * Step 10 — property / invariant aggregator for diagnostic export.
 */

import { describe, expect, it } from 'vitest'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { validateClassicPcap } from '../../../src/pcap/capture/validator'
import { mergePatchesStrict } from '../../../src/pcap/plan/mergePatchesStrict'
import { PlanInvariantError } from '../../../src/pcap/plan/planErrors'
import { diagnosticGoldenScenarios } from '../fixtures/diagnosticGoldenCorpus'
import { runDiagnosticExportPipeline } from '../helpers/diagnosticPipeline'

describe('diagnostic property gate (step 10)', () => {
  it('packet-count and length invariant across golden corpus', () => {
    for (const scenario of diagnosticGoldenScenarios()) {
      const { plan, built, packets } = runDiagnosticExportPipeline(
        scenario.packets,
        `${scenario.id}.pcap`,
        `prop-${scenario.id}`,
      )
      expect(plan.droppedPacketNumbers.length, scenario.id).toBe(0)
      expect(plan.packets.every((p) => p.truncatedLength == null), scenario.id).toBe(true)
      const reread = readClassicPcap(built.buffer)
      expect(reread.packets.length, scenario.id).toBe(packets.length)
      for (let i = 0; i < packets.length; i++) {
        expect(reread.packets[i]!.capturedLength, `${scenario.id}#${i}`).toBe(
          packets[i]!.capturedLength,
        )
        expect(reread.packets[i]!.originalLength, `${scenario.id}#${i}`).toBe(
          packets[i]!.originalLength,
        )
        expect(reread.packets[i]!.packetNumber, `${scenario.id}#${i}`).toBe(
          packets[i]!.packetNumber,
        )
      }
      const validation = validateClassicPcap(built.buffer)
      expect(validation.valid, scenario.id).toBe(true)
    }
  })

  it('patch overlap fails closed', () => {
    expect(() =>
      mergePatchesStrict(32, 0, [
        { offset: 4, data: new Uint8Array([1, 2, 3, 4]) },
        { offset: 6, data: new Uint8Array([9, 9]) },
      ]),
    ).toThrow(PlanInvariantError)
  })

  it('mapping injectivity: snapshot aliases unique per category among golden exports', () => {
    const scenario = diagnosticGoldenScenarios().find((s) => s.id === 'protocol-matrix')!
    const { snapshot } = runDiagnosticExportPipeline(scenario.packets, 'inject.pcap', 'inject')
    const byCategory = new Map<string, Set<string>>()
    for (const e of snapshot.entries) {
      const set = byCategory.get(e.category) ?? new Set()
      // Reserved / non-pseudonymized identities (broadcast, multicast, well-known ports)
      if (e.alias === e.canonical) continue
      expect(set.has(e.alias), `${e.category} alias collision ${e.alias}`).toBe(false)
      set.add(e.alias)
      byCategory.set(e.category, set)
    }
  })
})
