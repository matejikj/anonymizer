/**
 * Worker-backed PCAP plan rebuild port (Stage 9 production default).
 */

import {
  getPcapSession,
  updateSessionPlan,
  updateSessionDiscoveryAndPlan,
  filterPacketIndices,
  analysisFromWire,
} from '../ui/pcapSession'
import { usePcapStore } from '../ui/pcapStore'
import { cs } from '../../i18n/cs.ts'
import type { PcapPlanRebuildPort, PcapPlanRebuildResult } from './PcapPlanRebuildPort'
import type { PcapAnonymizationLevel } from './pcapAnonymizationLevel'
import { derivedPolicyView, presetToSanitizationPolicy } from './presets'
import { orchestratePlanRebuild, orchestrateViaWorkers } from '../processing/processingOrchestrator'
import { planFromWire } from '../processing/planWireAdapter'
import { containerFromWire } from '../processing/containerWireAdapter'
import { buildSessionCoverage } from '../coverage'

function applyExportHint(): void {
  const session = getPcapSession()
  if (!session) return
  usePcapStore.getState().setExportHint(
    session.statuses.anonymization === 'exposed'
      ? cs.pcap.export.exposedHint
      : session.statuses.anonymization === 'blocked'
        ? cs.pcap.export.blockedHint
        : null,
  )
}

export function createWorkerPcapPlanRebuildPort(): PcapPlanRebuildPort {
  let latestGeneration = 0
  let appliedGeneration = 0

  return {
    currentGeneration: () => latestGeneration,
    activeGeneration: () => appliedGeneration,
    shouldApply: (generation: number) => generation === latestGeneration,
    async rebuildPlan(level: PcapAnonymizationLevel): Promise<PcapPlanRebuildResult> {
      latestGeneration += 1
      const generation = latestGeneration

      usePcapStore.getState().setPlanGeneration(generation)
      usePcapStore.getState().setPlanStale(true)

      const session = getPcapSession()
      if (!session) {
        appliedGeneration = generation
        usePcapStore.getState().setActivePlanGeneration(generation)
        usePcapStore.getState().setPlanStale(false)
        return { generation, applied: true }
      }

      const profile = derivedPolicyView(level)
      const policy = presetToSanitizationPolicy(level)
      // PF-19: policy affects sanitization DISPOSITION (media drop/preserve, SIP fail-closed
      // handling, TTL/window preservation, heuristic scan on/off — which can even change which
      // entities get found), not just the mapped alias VALUES. The narrow rebuild below reuses
      // discovery's per-packet coverage/analysis verbatim, which is only correct when the
      // policy hasn't actually changed since discovery ran. Re-run full discovery under the
      // new policy whenever it has, so the privacy report / coverage tab / status badges stay
      // correct for the level actually applied — not whichever level the file was first opened
      // under.
      const policyChanged = JSON.stringify(policy) !== JSON.stringify(session.policy)

      if (policyChanged) {
        const result = await orchestrateViaWorkers({
          blob: session.sourceFile,
          fileName: session.fileName,
          format: session.format,
          policy,
          profile,
          generationId: session.generationId,
          sourceId: session.fileName,
        })

        if (!this.shouldApply(generation)) {
          return { generation, applied: false }
        }

        const container = containerFromWire(result.containerWire)
        const analysis = analysisFromWire(result.discoveryWire)
        const { unifiedCoverage, entityOccurrenceIndex } = buildSessionCoverage({
          packetCount: container.descriptors.length,
          analysis,
          packetDiscovery: container.packetDiscovery,
          entityOccurrences: result.discoveryWire.entityOccurrences,
          entityIntents: result.discoveryWire.intents.map((i) => ({
            category: i.category,
            canonical: i.canonical,
            packetIndex: i.packetIndex,
          })),
        })
        const plan = planFromWire(result.planWire, level)
        updateSessionDiscoveryAndPlan({
          analysis,
          packetDiscovery: container.packetDiscovery,
          unifiedCoverage,
          entityOccurrenceIndex,
          issues: container.issues,
          plan,
          profile,
          mappingRevision: result.snapshot.revision,
          coverageRollup: container.coverageRollup,
        })
      } else {
        const result = await orchestratePlanRebuild({
          blob: session.sourceFile,
          fileName: session.fileName,
          format: session.format,
          policy,
          profile,
          generationId: session.generationId,
          sourceId: session.fileName,
          mappingRevision: session.mappingRevision,
          analysis: session.analysis,
        })

        if (!this.shouldApply(generation)) {
          return { generation, applied: false }
        }

        const plan = planFromWire(result.planWire, level)
        updateSessionPlan(plan, profile, result.snapshot.revision)
      }

      const store = usePcapStore.getState()
      const indicesOriginal = filterPacketIndices(store.filter, store.displayFilterApplied, {
        dataView: 'original',
      })
      const indicesAnonymized = filterPacketIndices(store.filter, store.displayFilterApplied, {
        dataView: 'anonymized',
      })
      store.setFilteredIndicesForViews(indicesOriginal, indicesAnonymized)
      store.bumpSessionEpoch()

      appliedGeneration = generation
      usePcapStore.getState().setActivePlanGeneration(generation)
      usePcapStore.getState().setPlanStale(false)
      applyExportHint()
      // Mixed-set: keep CorrelationSourceRecord.plan in sync with the rebuilt session.
      void import('../../correlation/publishCorrelationPcapPlan').then((m) => {
        const sourceId = m.getActiveCorrelationPcapSourceId()
        if (sourceId) m.publishCorrelationPcapPlanFromSession(sourceId)
      })
      return { generation, applied: true }
    },
  }
}

/** Process-wide default port (overridable in tests). */
let defaultPort: PcapPlanRebuildPort = createWorkerPcapPlanRebuildPort()

export function getPcapPlanRebuildPort(): PcapPlanRebuildPort {
  return defaultPort
}

export function setPcapPlanRebuildPort(port: PcapPlanRebuildPort): void {
  defaultPort = port
}

export function resetPcapPlanRebuildPort(): void {
  defaultPort = createWorkerPcapPlanRebuildPort()
}
