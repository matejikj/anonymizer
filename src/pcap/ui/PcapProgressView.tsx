import { useEffect, useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore, type PcapProgress } from './pcapStore.ts'
import { cancelActiveOperation } from '../../app/sessionLifecycleCoordinator.ts'
import { formatBytes, formatPacketCount } from './formatters.ts'
import { ProgressSplash } from '../../design-system/ProgressSplash.tsx'

const TIP_COUNT = 4

// The pipeline's user-visible steps, in order. 'checking' (preflight) is near-instant and
// shown as "before step 1"; 'coverage' is not currently reachable by any real phase.
const STEP_PHASES: readonly PcapProgress['phase'][] = ['analyzing', 'building']

function stepLabelFor(phase: PcapProgress['phase']): string {
  return phase === 'building' ? cs.pcap.progress.building : cs.pcap.progress.analyzing
}

export function PcapProgressView() {
  const progress = usePcapStore((s) => s.progress)
  const [tipIndex, setTipIndex] = useState(0)
  const [elapsed, setElapsed] = useState(0)

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

  const phaseLabel =
    progress.phase === 'checking'
      ? cs.pcap.progress.checking
      : progress.phase === 'analyzing'
        ? cs.pcap.progress.analyzing
        : progress.phase === 'building'
          ? cs.pcap.progress.building
          : progress.phase === 'coverage'
            ? cs.pcap.progress.coverage
            : cs.pcap.progress.checking

  // Fraction of the CURRENT phase alone (0-1) — whichever unit it reports progress in.
  const withinPhaseFraction =
    progress.packetsTotal > 0
      ? progress.packetsDone / progress.packetsTotal
      : progress.bytesTotal > 0
        ? progress.bytesDone / progress.bytesTotal
        : 0

  const stepIndex = STEP_PHASES.indexOf(progress.phase)

  // Overall progress across the whole pipeline, for accessibility/consistency — always moves
  // forward (never drops when a phase transition happens, unlike a per-phase-only percent).
  const overallPercent =
    stepIndex < 0
      ? null
      : Math.min(100, Math.round(((stepIndex + Math.max(0, Math.min(1, withinPhaseFraction))) / STEP_PHASES.length) * 100))

  const detail =
    progress.packetsTotal > 0
      ? cs.pcap.progress.packets
          .replace('{done}', formatPacketCount(progress.packetsDone))
          .replace('{total}', formatPacketCount(progress.packetsTotal))
      : cs.pcap.progress.bytes
          .replace('{done}', formatBytes(progress.bytesDone))
          .replace('{total}', formatBytes(progress.bytesTotal))

  const tip = cs.pcap.progress.tips[tipIndex % cs.pcap.progress.tips.length]!

  const stepBar = (
    <div className="pcap-progress-steps-wrap">
      <div
        className="pcap-progress-steps"
        role="group"
        aria-label={cs.pcap.progress.stepLabel
          .replace('{current}', String(Math.max(1, stepIndex + 1)))
          .replace('{total}', String(STEP_PHASES.length))}
      >
        {STEP_PHASES.map((phase, i) => {
          const state = i < stepIndex ? 'done' : i === stepIndex ? 'active' : 'pending'
          const fillPercent = i < stepIndex ? 100 : i === stepIndex ? Math.round(withinPhaseFraction * 100) : 0
          return (
            <div key={phase} className={`pcap-progress-steps__seg pcap-progress-steps__seg--${state}`}>
              <span className="pcap-progress-steps__track" aria-hidden="true">
                <span className="pcap-progress-steps__fill" style={{ width: `${fillPercent}%` }} />
              </span>
              <span className="pcap-progress-steps__label">{stepLabelFor(phase)}</span>
            </div>
          )
        })}
      </div>
      {overallPercent != null ? (
        <p className="pcap-progress-steps__percent type-mono">{overallPercent} %</p>
      ) : null}
    </div>
  )

  return (
    <ProgressSplash
      className="pcap-progress pcap-progress--splash"
      testId="pcap-progress"
      eyebrow={cs.pcap.progress.working}
      title={phaseLabel}
      fileName={progress.fileName}
      percent={overallPercent}
      indeterminate={stepIndex < 0}
      detail={detail}
      tip={tip}
      elapsedSec={elapsed}
      onCancel={progress.cancellable ? () => cancelActiveOperation() : undefined}
      cancelLabel={cs.pcap.progress.cancel}
      cancelTestId="pcap-cancel"
      barSlot={stepBar}
    />
  )
}
