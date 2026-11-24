import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import { resetApplication } from '../../app/sessionLifecycleCoordinator.ts'
import { getSessionModel } from './sessionModel.ts'
import { BYTES_PER_MIB } from '../import-log/inputLimits.ts'
import { getDualLogBridge } from './editorBridge.ts'
import { listOccurrences, stepOccurrenceIndex } from './occurrences.ts'
import { SecuritySummaryBar } from '../review/SecuritySummaryBar.tsx'
import { ExportBar } from '../export-log/ExportBar.tsx'
import { Button, WorkspaceChrome } from '../../design-system/index.ts'

export type WorkspaceCommandStripVariant = 'standalone' | 'correlation'

export interface WorkspaceCommandStripProps {
  /** `correlation` = embedded in a mixed set: no close/export, file-local findings label. */
  readonly variant?: WorkspaceCommandStripVariant
}

/** File-level text chrome — same WorkspaceChrome contract as PCAP toolbar. */
export function WorkspaceCommandStrip({ variant = 'standalone' }: WorkspaceCommandStripProps) {
  const phase = useAppStore((s) => s.phase)
  const wrapEnabled = useAppStore((s) => s.wrapEnabled)
  const occurrenceIndex = useAppStore((s) => s.occurrenceIndex)
  const focusedLine = useAppStore((s) => s.focusedLine)
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const session = sessionEpoch >= 0 ? getSessionModel() : null
  const meta = session?.meta
  const inSet = variant === 'correlation'
  const occurrences =
    session != null
      ? listOccurrences(session.packed, session.entitySummaries, session.plan.replacements)
      : []

  const onCloseLog = () => {
    resetApplication()
  }

  const onToggleWrap = () => {
    useAppStore.getState().setWrapEnabled(!wrapEnabled)
  }

  const jumpOccurrence = (delta: number) => {
    const bridge = getDualLogBridge()
    if (!bridge || occurrences.length === 0) return
    const next = stepOccurrenceIndex(occurrenceIndex, delta, occurrences.length)
    const occ = occurrences[next]
    if (!occ) return
    bridge.jumpToMatchIndex(occ.matchIndex)
  }

  if (phase === 'importing') {
    return null
  }

  if (!meta) return null

  const findingsLabel = inSet ? cs.workspace.findingsInFile : cs.workspace.findingsNav
  const occLabel =
    occurrences.length === 0
      ? cs.workspace.occurrenceNone
      : occurrenceIndex < 0
        ? cs.workspace.occurrenceUnset.replace('{total}', String(occurrences.length))
        : cs.workspace.occurrenceOf
            .replace('{current}', String(occurrenceIndex + 1))
            .replace('{total}', String(occurrences.length))

  return (
    <WorkspaceChrome
      embedded={inSet}
      mode={inSet ? 'embedded' : 'standalone'}
      testId={inSet ? 'correlation-text-toolbar' : 'workspace-toolbar'}
      context={
        <div className="workspace-chrome__meta command-strip__meta">
          {inSet ? null : (
            <Button
              variant="secondary"
              data-testid="close-log"
              title={cs.workspace.closeLogHint}
              aria-description={cs.workspace.closeLogHint}
              onClick={onCloseLog}
            >
              {cs.workspace.closeLog}
            </Button>
          )}
          <span
            className="workspace-chrome__file command-strip__file"
            data-testid="session-file-name"
            title={meta.fileName ?? cs.workspace.untitled}
          >
            {meta.fileName ?? cs.workspace.untitled}
          </span>
          <span className="workspace-chrome__stats command-strip__stats">
            <span className="command-strip__stat">
              {meta.lineCount.toLocaleString('cs-CZ')} {cs.workspace.lines}
            </span>
            <span className="command-strip__stat">
              {(meta.byteLength / BYTES_PER_MIB).toFixed(2)} MiB
            </span>
            {meta.mode === 'large' ? (
              <span className="badge badge--large" data-testid="large-log-badge">
                {cs.workspace.largeLogBadge}
              </span>
            ) : null}
            <span className="command-strip__stat" data-testid="focused-line">
              {cs.workspace.lineLabel} {focusedLine}
            </span>
          </span>
        </div>
      }
      tools={
        <div className="workspace-chrome__nav command-strip__nav" role="group" aria-label={findingsLabel}>
          <span className="workspace-chrome__nav-label command-strip__nav-label">{findingsLabel}</span>
          <label className="wrap-toggle wrap-toggle--compact">
            <input
              type="checkbox"
              checked={wrapEnabled}
              onChange={onToggleWrap}
              data-testid="wrap-toggle"
            />
            <span>{cs.workspace.wrapLinesShort}</span>
          </label>
          <Button
            variant="ghost"
            data-testid="occ-prev"
            disabled={occurrences.length === 0}
            aria-label={cs.workspace.prevFinding}
            onClick={() => jumpOccurrence(-1)}
          >
            {cs.workspace.prevFindingShort}
          </Button>
          <Button
            variant="ghost"
            data-testid="occ-next"
            disabled={occurrences.length === 0}
            aria-label={cs.workspace.nextFinding}
            onClick={() => jumpOccurrence(1)}
          >
            {cs.workspace.nextFindingShort}
          </Button>
          <span className="command-strip__stat command-strip__occ" data-testid="occ-counter">
            {occLabel}
          </span>
        </div>
      }
      status={<SecuritySummaryBar compact />}
      primary={
        inSet ? undefined : (
          <div className="workspace-chrome__actions command-strip__actions">
            <ExportBar />
          </div>
        )
      }
    />
  )
}

export function OversizedLineBanner() {
  const sessionEpoch = useAppStore((s) => s.sessionEpoch)
  const session = sessionEpoch >= 0 ? getSessionModel() : null
  const lines = session?.meta.oversizedLines ?? []
  if (lines.length === 0) return null
  const preview = lines.slice(0, 5).join(', ')
  const more = lines.length > 5 ? ` (+${lines.length - 5})` : ''
  return (
    <p className="oversized-banner" role="status" data-testid="oversized-banner">
      {cs.workspace.oversizedLines}: {preview}
      {more}
    </p>
  )
}
