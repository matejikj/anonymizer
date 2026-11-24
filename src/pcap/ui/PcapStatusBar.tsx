import { useMemo } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { getPcapSession, getPacketCount, getPacketRowMeta } from './pcapSession.ts'
import { getPcapCoverageViewModel } from './getPcapCoverageViewModel.ts'
import { formatPacketCount } from './formatters.ts'
import { findRuleBySlot, NO_COLOR_SLOT } from '../coloring'
import { compileColoringRules } from '../coloring/compileColoringRules'

export function PcapStatusBar() {
  const epoch = usePcapStore((s) => s.sessionEpoch)
  const filteredIndices = usePcapStore((s) => s.filteredIndices)
  const filteredIndicesOriginal = usePcapStore((s) => s.filteredIndicesOriginal)
  const filteredIndicesAnonymized = usePcapStore((s) => s.filteredIndicesAnonymized)
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const selectedFieldPath = usePcapStore((s) => s.selectedFieldPath)
  const displayFilterApplied = usePcapStore((s) => s.displayFilterApplied)
  const displayFilterStatus = usePcapStore((s) => s.displayFilterStatus)
  const dataView = usePcapStore((s) => s.dataView)
  const compareLayout = usePcapStore((s) => s.compareLayout)
  const focusedPane = usePcapStore((s) => s.focusedPane)
  const colorizePacketList = usePcapStore((s) => s.colorizePacketList)
  const coloringRules = usePcapStore((s) => s.coloringRules)
  const coloringRulesRevision = usePcapStore((s) => s.coloringRulesRevision)
  const colorSlotsOriginal = usePcapStore((s) => s.colorSlotsOriginal)
  const colorSlotsAnonymized = usePcapStore((s) => s.colorSlotsAnonymized)
  const activeProfile = usePcapStore((s) => s.activeProfile)
  const exportBusy = usePcapStore((s) => s.exportBusy)
  const exportMessage = usePcapStore((s) => s.exportMessage)
  const session = epoch >= 0 ? getPcapSession() : null
  const vm = getPcapCoverageViewModel()

  const colorRuleName = useMemo(() => {
    if (!colorizePacketList || selectedPacketIndex < 0) return null
    const pane = compareLayout === 'dual' ? focusedPane : dataView
    const slots = pane === 'original' ? colorSlotsOriginal : colorSlotsAnonymized
    const slot = slots[selectedPacketIndex] ?? NO_COLOR_SLOT
    if (slot === NO_COLOR_SLOT) return null
    const compiled = compileColoringRules(coloringRules, coloringRulesRevision)
    return findRuleBySlot(compiled.rules, slot)?.name ?? null
  }, [
    colorizePacketList,
    selectedPacketIndex,
    compareLayout,
    focusedPane,
    dataView,
    colorSlotsOriginal,
    colorSlotsAnonymized,
    coloringRules,
    coloringRulesRevision,
  ])

  const fieldMessage = useMemo(() => {
    if (displayFilterStatus === 'invalid') {
      return cs.pcap.workspace.statusFilterInvalid
    }
    const dualEmpty =
      compareLayout === 'dual' &&
      filteredIndicesOriginal.length === 0 &&
      filteredIndicesAnonymized.length === 0
    const singleEmpty = compareLayout !== 'dual' && filteredIndices.length === 0
    if (displayFilterApplied && (dualEmpty || singleEmpty)) {
      return cs.pcap.workspace.statusFilterEmpty
    }
    if (selectedFieldPath) {
      return cs.pcap.workspace.statusFieldSelected.replace('{path}', selectedFieldPath)
    }
    const meta = getPacketRowMeta(selectedPacketIndex)
    if (meta.descriptor) {
      return cs.pcap.workspace.statusPacketSelected.replace('{n}', String(meta.descriptor.packetNumber))
    }
    if (displayFilterApplied) {
      return cs.pcap.workspace.statusFilterActive.replace('{expr}', displayFilterApplied)
    }
    return cs.pcap.workspace.statusReady
  }, [
    displayFilterApplied,
    displayFilterStatus,
    filteredIndices.length,
    filteredIndicesOriginal.length,
    filteredIndicesAnonymized.length,
    selectedFieldPath,
    selectedPacketIndex,
    compareLayout,
  ])

  if (!session) return null

  const total = getPacketCount()
  const dropped = session.statuses.droppedCount
  const exportState = exportBusy
    ? cs.pcap.workspace.statusExporting
    : exportMessage
      ? exportMessage
      : vm?.summary.canExport
        ? cs.pcap.workspace.statusExportReady
        : cs.pcap.workspace.statusExportBlocked

  const countsLabel =
    compareLayout === 'dual'
      ? cs.pcap.workspace.statusDisplayedDual
          .replace('{orig}', formatPacketCount(filteredIndicesOriginal.length))
          .replace('{anon}', formatPacketCount(filteredIndicesAnonymized.length))
          .replace('{total}', formatPacketCount(total))
          .replace('{dropped}', formatPacketCount(dropped))
      : cs.pcap.workspace.statusDisplayed
          .replace('{displayed}', formatPacketCount(filteredIndices.length))
          .replace('{total}', formatPacketCount(total))
          .replace('{dropped}', formatPacketCount(dropped))

  return (
    <footer className="pcap-status-bar" data-testid="pcap-status-bar" role="contentinfo">
      <span className="pcap-status-bar__field" data-testid="pcap-status-field" title={fieldMessage}>
        {fieldMessage}
      </span>
      {colorRuleName ? (
        <span className="pcap-status-bar__color-rule" data-testid="pcap-status-color-rule">
          {cs.pcap.coloring.statusRule.replace('{name}', colorRuleName)}
        </span>
      ) : null}
      <span className="pcap-status-bar__counts" data-testid="pcap-status-counts">
        {countsLabel}
      </span>
      <span className="pcap-status-bar__profile" title={activeProfile.name}>
        {activeProfile.name}
      </span>
      <span
        className={`pcap-status-bar__view${(compareLayout === 'dual' ? focusedPane : dataView) === 'original' ? ' pcap-status-bar__view--original' : ''}`}
        data-testid="pcap-status-data-view"
      >
        {compareLayout === 'dual'
          ? cs.pcap.workspace.statusFocus.replace(
              '{pane}',
              focusedPane === 'original'
                ? cs.pcap.workspace.dataViewOriginal
                : cs.pcap.workspace.dataViewAnonymized,
            )
          : dataView === 'original'
            ? cs.pcap.workspace.dataViewOriginal
            : cs.pcap.workspace.dataViewAnonymized}
      </span>
      <span
        className={`pcap-status-bar__export${vm?.summary.canExport ? '' : ' pcap-status-bar__export--blocked'}`}
        data-testid="pcap-status-export"
        role="status"
      >
        {exportState}
      </span>
    </footer>
  )
}
