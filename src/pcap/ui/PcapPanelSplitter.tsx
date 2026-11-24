import { useCallback, useRef, type KeyboardEvent, type ReactNode } from 'react'
import { cs } from '../../i18n/cs.ts'
import { MIN_PANEL_PX } from './pcapUiPrefs.ts'

export interface PcapPanelSplitterProps {
  readonly orientation: 'horizontal' | 'vertical'
  readonly ratio: number
  readonly onRatioChange: (ratio: number) => void
  readonly primary: ReactNode
  readonly secondary: ReactNode
  readonly testId?: string
}

export function PcapPanelSplitter({
  orientation,
  ratio,
  onRatioChange,
  primary,
  secondary,
  testId = 'pcap-panel-splitter',
}: PcapPanelSplitterProps) {
  const rootRef = useRef<HTMLDivElement>(null)
  const isVertical = orientation === 'vertical'

  const applyRatio = useCallback(
    (next: number) => {
      onRatioChange(Math.min(0.82, Math.max(0.18, next)))
    },
    [onRatioChange],
  )

  const onPointerDown = useCallback(
    (event: React.PointerEvent<HTMLDivElement>) => {
      event.preventDefault()
      const root = rootRef.current
      if (!root) return
      const rect = root.getBoundingClientRect()
      const start = isVertical ? event.clientY : event.clientX
      const startRatio = ratio
      const total = isVertical ? rect.height : rect.width

      const onMove = (ev: PointerEvent) => {
        const current = isVertical ? ev.clientY : ev.clientX
        const delta = current - start
        applyRatio(startRatio + delta / total)
      }
      const onUp = () => {
        window.removeEventListener('pointermove', onMove)
        window.removeEventListener('pointerup', onUp)
      }
      window.addEventListener('pointermove', onMove)
      window.addEventListener('pointerup', onUp)
    },
    [applyRatio, isVertical, ratio],
  )

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const step = event.shiftKey ? 0.08 : 0.03
    if (isVertical) {
      if (event.key === 'ArrowUp') applyRatio(ratio - step)
      else if (event.key === 'ArrowDown') applyRatio(ratio + step)
      else return
    } else {
      if (event.key === 'ArrowLeft') applyRatio(ratio - step)
      else if (event.key === 'ArrowRight') applyRatio(ratio + step)
      else return
    }
    event.preventDefault()
  }

  const primarySize = `${Math.round(ratio * 1000) / 10}%`
  const secondarySize = `${Math.round((1 - ratio) * 1000) / 10}%`

  return (
    <div
      ref={rootRef}
      className={`pcap-panel-split pcap-panel-split--${orientation}`}
      data-testid={testId}
      style={
        isVertical
          ? { gridTemplateRows: `minmax(${MIN_PANEL_PX}px, ${primarySize}) 6px minmax(${MIN_PANEL_PX}px, ${secondarySize})` }
          : { gridTemplateColumns: `minmax(${MIN_PANEL_PX}px, ${primarySize}) 6px minmax(${MIN_PANEL_PX}px, ${secondarySize})` }
      }
    >
      <div className="pcap-panel-split__primary">{primary}</div>
      <div
        className="pcap-panel-split__handle"
        role="separator"
        aria-orientation={isVertical ? 'horizontal' : 'vertical'}
        aria-label={cs.pcap.workspace.splitterLabel}
        aria-valuemin={18}
        aria-valuemax={82}
        aria-valuenow={Math.round(ratio * 100)}
        tabIndex={0}
        data-testid={`${testId}-handle`}
        onPointerDown={onPointerDown}
        onKeyDown={onKeyDown}
      />
      <div className="pcap-panel-split__secondary">{secondary}</div>
    </div>
  )
}
