/**
 * Mount global PCAP session from a correlation source for full workspace UI.
 */

import { getActivePcapProfile } from '../pcap/profile/activePcapProfile'
import {
  createSlimPcapSession,
  filterPacketIndices,
  getPcapSession,
} from '../pcap/ui/pcapSession'
import { createIdlePcapProgress, usePcapStore } from '../pcap/ui/pcapStore'
import { prepareNewPcapSession, teardownPcapSession } from '../pcap/ui/pcapSessionLifecycle'
import type { PcapSourceDescriptor } from '../pcap/ui/pcapSourceDescriptor'
import type { PcapSourceDiscovery, PcapSourcePlan } from './types'
import { getSourceScroll } from './correlationReviewModel'
import {
  beginSourceMount,
  clearSourceMountToken,
  defaultPcapSourceUi,
  isSourceMountCurrent,
  makeSourceMountToken,
  type PcapSourceUiContext,
} from './correlationSourceUiContext'
import { refreshPcapFilter } from '../pcap/ui/pcapLoadController'

export function mountCorrelationPcapEditor(
  discovery: PcapSourceDiscovery,
  plan: PcapSourcePlan,
  file: File,
  options?: {
    readonly sourceId?: string
    readonly ui?: PcapSourceUiContext
  },
): () => void {
  const sourceId = options?.sourceId ?? discovery.sourceId
  const token = makeSourceMountToken(sourceId, plan.generationId)
  beginSourceMount(token)

  const container = discovery.container
  const srcDiscovery = discovery.discovery
  const profile = getActivePcapProfile()
  const ui = options?.ui ?? defaultPcapSourceUi()

  const descriptor: PcapSourceDescriptor = {
    fileName: discovery.fileName,
    fileSize: discovery.byteLength,
    format: discovery.format,
    sourceFile: file,
    descriptors: container.descriptors,
    checkpoints: container.checkpoints,
    issues: container.issues,
    classicHeader: container.classicHeader,
    pcapngSections: container.pcapngSections as PcapSourceDescriptor['pcapngSections'],
    pcapngInterfaces: container.pcapngInterfaces as PcapSourceDescriptor['pcapngInterfaces'],
  }

  teardownPcapSession()

  if (!isSourceMountCurrent(token)) {
    return () => undefined
  }

  const session = createSlimPcapSession({
    descriptor,
    generationId: discovery.generationId,
    analysis: srcDiscovery.analysis,
    packetDiscovery: srcDiscovery.packetDiscovery,
    unifiedCoverage: srcDiscovery.unifiedCoverage,
    entityOccurrenceIndex: srcDiscovery.entityOccurrenceIndex,
    coverageRollup: container.coverageRollup,
    plan: plan.plan,
    mappingRevision: plan.mappingRevision,
    profile,
  })

  prepareNewPcapSession(session.generation, discovery.generationId)

  if (!isSourceMountCurrent(token)) {
    teardownPcapSession(session.generation)
    return () => undefined
  }

  const store = usePcapStore.getState()
  store.setFilter(ui.filter)
  store.setCompareLayout(ui.compareLayout)
  store.setDataView(ui.dataView)
  store.setDetailBytesLayout(ui.detailBytesLayout)
  store.setInspectorOpen(ui.inspectorOpen)
  store.setInspectorTab(ui.inspectorTab)
  store.setDetailTab(ui.detailTab)
  if (ui.selectedFieldPath) store.setSelectedFieldPath(ui.selectedFieldPath)
  if (ui.selectedByteOffset != null) store.setSelectedByteOffset(ui.selectedByteOffset)

  if (ui.displayFilterApplied) {
    store.applyDisplayFilter(ui.displayFilterApplied)
  } else if (ui.displayFilterDraft) {
    store.setDisplayFilterDraft(ui.displayFilterDraft, 'incomplete', null)
  } else {
    store.clearDisplayFilter()
  }

  const appliedFilter = store.displayFilterApplied
  const indicesOriginal = filterPacketIndices(store.filter, appliedFilter, { dataView: 'original' })
  const indicesAnonymized = filterPacketIndices(store.filter, appliedFilter, {
    dataView: 'anonymized',
  })
  store.setFilteredIndicesForViews(indicesOriginal, indicesAnonymized)

  const rememberedPacketIndex = getSourceScroll(discovery.sourceId)?.packetIndex
  const preferred =
    rememberedPacketIndex !== undefined
      ? rememberedPacketIndex
      : ui.selectedPacketIndex >= 0
        ? ui.selectedPacketIndex
        : undefined
  const defaultIndex =
    indicesAnonymized[0] ?? indicesOriginal[0] ?? (container.descriptors.length > 0 ? 0 : -1)
  const initialIndex =
    preferred !== undefined && preferred < container.descriptors.length ? preferred : defaultIndex
  store.setSelectedPacketIndex(initialIndex)
  store.bumpSessionEpoch()
  store.setProgress(createIdlePcapProgress())
  store.setPhase('workspace')
  store.setExportHint(null)
  store.setExportBusy(false)
  store.setExportPhase('idle')
  store.setExportMessage(null)

  if (appliedFilter) {
    void refreshPcapFilter()
  }

  return () => {
    if (isSourceMountCurrent(token)) clearSourceMountToken()
    teardownPcapSession(session.generation)
    if (!getPcapSession()) {
      usePcapStore.getState().setPhase('empty')
    }
  }
}
