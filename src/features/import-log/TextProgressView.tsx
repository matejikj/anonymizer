import { useCallback, useEffect, useMemo, useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import { cancelActiveOperation } from '../../app/sessionLifecycleCoordinator.ts'
import type { ImportPhase } from './importProgress.ts'
import { formatBytes } from '../../pcap/ui/formatters.ts'
import { ProgressSplash } from '../../design-system/ProgressSplash.tsx'

const TIP_COUNT = 4

function phaseTitle(phase: ImportPhase): string {
  switch (phase) {
    case 'checking':
      return cs.textProgress.checking
    case 'loading':
      return cs.textProgress.loading
    case 'analyzing':
      return cs.textProgress.analyzing
    case 'preparing':
      return cs.textProgress.preparing
    default:
      return cs.textProgress.analyzing
  }
}

function useDisplayPercent(real: number | null, startedAt: number, active: boolean): number | null {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!active) return
    const id = window.setInterval(() => setTick((t) => t + 1), 1000)
    return () => window.clearInterval(id)
  }, [active])
  return useMemo(() => {
    if (real != null) return real
    if (!active || startedAt <= 0) return null
    const elapsed = (Date.now() - startedAt) / 1000
    return Math.min(22, Math.round(elapsed * 1.8))
    // eslint-disable-next-line react-hooks/exhaustive-deps -- tick drives periodic refresh
  }, [real, startedAt, active, tick])
}

export function TextProgressView() {
  const progress = useAppStore((s) => s.importProgress)
  const [tipIndex, setTipIndex] = useState(0)
  const [elapsed, setElapsed] = useState(0)

  const realPercent =
    progress.totalBytes && progress.totalBytes > 0
      ? Math.min(100, Math.round((progress.processedBytes / progress.totalBytes) * 100))
      : null
  const displayPercent = useDisplayPercent(realPercent, progress.startedAt, progress.phase !== 'idle')
  const indeterminate = displayPercent == null || displayPercent < 8

  useEffect(() => {
    if (progress.startedAt <= 0) return
    const tick = () => setElapsed(Math.max(0, Math.round((Date.now() - progress.startedAt) / 1000)))
    tick()
    const id = window.setInterval(tick, 1000)
    return () => window.clearInterval(id)
  }, [progress.startedAt])

  useEffect(() => {
    const id = window.setInterval(() => {
      setTipIndex((i) => (i + 1) % TIP_COUNT)
    }, 3200)
    return () => window.clearInterval(id)
  }, [])

  const tip = cs.textProgress.tips[tipIndex % cs.textProgress.tips.length]!
  const fileLabel = progress.fileName ?? cs.workspace.untitled
  const detail =
    progress.totalBytes && progress.totalBytes > 0
      ? cs.textProgress.bytes
          .replace('{done}', formatBytes(progress.processedBytes))
          .replace('{total}', formatBytes(progress.totalBytes))
      : progress.processedLines > 0
        ? cs.textProgress.lines.replace('{n}', progress.processedLines.toLocaleString('cs-CZ'))
        : progress.message

  const onCancel = useCallback(() => {
    cancelActiveOperation()
  }, [])

  return (
    <ProgressSplash
      className="text-progress text-progress--splash"
      testId="import-progress"
      eyebrow={cs.textProgress.working}
      title={phaseTitle(progress.phase)}
      fileName={fileLabel}
      percent={displayPercent}
      indeterminate={indeterminate}
      detail={detail}
      tip={tip}
      elapsedSec={elapsed}
      onCancel={onCancel}
      cancelLabel={cs.textProgress.cancel}
      cancelTestId="cancel-analysis"
    />
  )
}
