import { useEffect, type ReactNode } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { getPcapSession } from './pcapSession.ts'
import { PcapFilterBar } from './PcapFilterBar.tsx'
import { PcapComparisonWorkspace } from './PcapComparisonWorkspace.tsx'
import { PcapInspector } from './PcapInspector.tsx'
import { usePcapPacketColoring } from './usePcapPacketColoring.ts'
import { useAppStore } from '../../app/store.ts'

function useLayoutModeListener() {
  const setLayoutMode = usePcapStore((s) => s.setLayoutMode)
  useEffect(() => {
    const update = () => {
      setLayoutMode(window.innerWidth < 900 ? 'narrow' : 'desktop')
    }
    update()
    window.addEventListener('resize', update)
    return () => window.removeEventListener('resize', update)
  }, [setLayoutMode])
}

function useCaptureKeyboardShortcuts() {
  const compareLayout = usePcapStore((s) => s.compareLayout)
  const focusedPane = usePcapStore((s) => s.focusedPane)
  const filteredIndicesOriginal = usePcapStore((s) => s.filteredIndicesOriginal)
  const filteredIndicesAnonymized = usePcapStore((s) => s.filteredIndicesAnonymized)
  const filteredIndices = usePcapStore((s) => s.filteredIndices)
  const selectedPacketIndex = usePcapStore((s) => s.selectedPacketIndex)
  const setSelectedPacketIndex = usePcapStore((s) => s.setSelectedPacketIndex)
  const pushSelectionSnapshot = usePcapStore((s) => s.pushSelectionSnapshot)
  const navigateSelectionHistory = usePcapStore((s) => s.navigateSelectionHistory)
  const toggleMarkedPacket = usePcapStore((s) => s.toggleMarkedPacket)

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      const inInput =
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.tagName === 'SELECT' ||
          target.isContentEditable)
      if (inInput) return

      const activeIndices =
        compareLayout === 'dual'
          ? focusedPane === 'original'
            ? filteredIndicesOriginal
            : filteredIndicesAnonymized
          : filteredIndices

      const count = activeIndices.length
      const pos = activeIndices.indexOf(selectedPacketIndex)

      const selectAt = (nextPos: number) => {
        const idx = activeIndices[nextPos]
        if (idx === undefined) return
        setSelectedPacketIndex(idx)
        pushSelectionSnapshot({ packetIndex: idx, fieldPath: null, byteOffset: null })
      }

      if (event.key === 'F7' || ((event.ctrlKey || event.metaKey) && event.key === 'ArrowUp')) {
        event.preventDefault()
        if (count > 0) selectAt(Math.max(0, pos <= 0 ? 0 : pos - 1))
        return
      }
      if (event.key === 'F8' || ((event.ctrlKey || event.metaKey) && event.key === 'ArrowDown')) {
        event.preventDefault()
        if (count > 0) selectAt(Math.min(count - 1, pos < 0 ? 0 : pos + 1))
        return
      }
      if (event.altKey && event.key === 'ArrowLeft') {
        event.preventDefault()
        navigateSelectionHistory(-1)
        return
      }
      if (event.altKey && event.key === 'ArrowRight') {
        event.preventDefault()
        navigateSelectionHistory(1)
        return
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'm') {
        if (selectedPacketIndex >= 0) {
          event.preventDefault()
          toggleMarkedPacket(selectedPacketIndex)
        }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [
    compareLayout,
    focusedPane,
    filteredIndicesOriginal,
    filteredIndicesAnonymized,
    filteredIndices,
    selectedPacketIndex,
    setSelectedPacketIndex,
    pushSelectionSnapshot,
    navigateSelectionHistory,
    toggleMarkedPacket,
  ])
}

export interface PcapCaptureStageProps {
  readonly loading?: boolean
  readonly loadingContent?: ReactNode
}

export function PcapCaptureStage({ loading = false, loadingContent }: PcapCaptureStageProps) {
  const epoch = usePcapStore((s) => s.sessionEpoch)
  const layoutMode = usePcapStore((s) => s.layoutMode)
  const compareLayout = usePcapStore((s) => s.compareLayout)
  const inspectorOpen = usePcapStore((s) => s.inspectorOpen)
  const phase = useAppStore((s) => s.phase)
  void phase
  const session = epoch >= 0 ? getPcapSession() : null

  useLayoutModeListener()
  useCaptureKeyboardShortcuts()
  usePcapPacketColoring(epoch)

  if (!session) return null

  return (
    <div
      className={`pcap-capture-stage${inspectorOpen ? ' pcap-capture-stage--inspector-open' : ''}`}
      data-testid="pcap-capture-stage"
      data-layout={layoutMode}
      data-compare-layout={compareLayout}
    >
      <div className="pcap-capture-stage__center">
        <PcapFilterBar />
        {loading ? (
          <div className="pcap-workspace__loading" role="status" data-testid="pcap-workspace-loading">
            {loadingContent ?? cs.pcap.progress.analyzing}
          </div>
        ) : (
          <PcapComparisonWorkspace />
        )}
      </div>
      <PcapInspector dock />
    </div>
  )
}
