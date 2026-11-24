import { useRef, useState } from 'react'
import { IconCheck, IconX } from '../../components/ui/icons.tsx'
import { StatusChip } from '../../components/ui/StatusChip.tsx'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'
import {
  BundleCancelledError,
  BundleLifecycleError,
  cancelBundleJob,
  exportCorrelationMappingBundle,
} from '../mapping-bundle/bundleController.ts'
import { MappingBundleExportDialog } from '../mapping-bundle/MappingBundleDialogs.tsx'
import { Badge, Button, RaisedPanel } from '../../design-system/index.ts'
import { getCorrelationCompletionState } from '../../correlation/export/correlationExportModel.ts'
import { getLastSupportBundleOmissions } from '../../correlation/import/stagingModel.ts'
import {
  enterCorrelationReviewPhase,
  finishCorrelationSessionAndClear,
} from '../../correlation/correlationWorkspaceController.ts'
import {
  gateBadgeFromShareableWithAi,
  normalizeGateResult,
  type GateResult,
} from '../../pcap/trust'

function completionBadgeLabel(gate: GateResult, partial: boolean): string {
  if (gate === 'AI_READY') return cs.correlationCompletion.aiReadyBadge
  if (gate === 'AI_READY_WITH_GAPS') return cs.correlationCompletion.aiReadyWithGapsBadge
  if (partial) return cs.correlationCompletion.partialBadge
  return cs.correlationCompletion.notAiReadyBadge
}

export function CorrelationCompletionView() {
  void useAppStore((s) => s.correlationEpoch)
  const completion = getCorrelationCompletionState()
  const [bundleOpen, setBundleOpen] = useState(false)
  const [bundleBusy, setBundleBusy] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  if (!completion) {
    return <p>{cs.correlationCompletion.missing}</p>
  }

  const dataFiles = completion.dataFiles ?? completion.exportedFiles.filter((f) => f !== 'correlation-manifest.json')
  const companionFiles = completion.companionFiles ?? completion.exportedFiles.filter((f) => f === 'correlation-manifest.json')
  const skippedFiles = completion.skippedFiles ?? []
  const bundleOmitted = getLastSupportBundleOmissions()
  const shareableWithAi = completion.shareableWithAi === true
  const gateBadge: GateResult =
    normalizeGateResult(completion.gateBadge)
    ?? gateBadgeFromShareableWithAi(shareableWithAi)
  const downloadUnverified = completion.downloadUnverified === true

  const closeBundle = () => {
    if (bundleBusy) {
      abortRef.current?.abort()
      cancelBundleJob()
    }
    setBundleOpen(false)
    setBundleBusy(false)
  }

  const runBundleExport = async () => {
    abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac
    setBundleBusy(true)
    try {
      await exportCorrelationMappingBundle({ signal: ac.signal })
      useAppStore.getState().setToast({ message: cs.bundle.exported })
      setBundleOpen(false)
    } catch (err) {
      if (err instanceof BundleCancelledError) {
        useAppStore.getState().setToast({ message: cs.bundle.cancelled })
        return
      }
      const message =
        err instanceof BundleLifecycleError && err.code === 'bundle-empty'
          ? cs.bundle.emptyMapping
          : err instanceof Error
            ? err.message
            : cs.bundle.failed
      useAppStore.getState().setToast({ message })
    } finally {
      setBundleBusy(false)
      abortRef.current = null
    }
  }

  // T67 — WITH_GAPS is informational green, not amber review.
  const safeTone = 'ok' as const
  const badge = completionBadgeLabel(gateBadge, completion.partial === true)
  const blockMod = ' corr-completion__block--ok'

  const filesLabel = cs.correlationCompletion.filesExported(dataFiles.length)
  const outcomeSummary =
    gateBadge === 'AI_READY'
      ? `${cs.pcap.outcome.summaryLevelDiagnostic} ${cs.pcap.outcome.summaryAiReady.replace('{protocols}', filesLabel)}`
      : gateBadge === 'AI_READY_WITH_GAPS'
        ? `${cs.pcap.outcome.summaryLevelDiagnostic} ${cs.pcap.outcome.summaryWithGaps
            .replace('{protocols}', filesLabel)
            .replace('{gaps}', cs.pcap.outcome.summaryGenericGaps)}`
        : `${cs.pcap.outcome.summaryLevelDiagnostic} ${cs.pcap.outcome.summaryInternalFallback.replace('{protocols}', filesLabel)}`

  return (
    <section className="corr-completion" data-testid="correlation-completion-view">
      <RaisedPanel
        className="anonymization-outcome corr-completion__outcome"
        data-testid="correlation-completion-outcome"
        data-gate={gateBadge}
      >
        <header className="anonymization-outcome__head">
          <h2 className="anonymization-outcome__title type-section-title">{cs.pcap.outcome.title}</h2>
          <span data-testid="correlation-completion-outcome-gate" data-gate={gateBadge}>
            <Badge tone="safe">
              <StatusChip tone={safeTone} label={badge} compact />
              <span className="anonymization-outcome__gate-label">{badge}</span>
            </Badge>
          </span>
        </header>
        <p className="anonymization-outcome__summary" role="status" data-testid="correlation-completion-outcome-summary">
          {outcomeSummary}
        </p>
      </RaisedPanel>

      <section
        className={`corr-completion__block corr-completion__block--safe${blockMod}`}
        aria-labelledby="corr-completion-safe-title"
        data-status={
          gateBadge === 'AI_READY' ? 'safe' : gateBadge === 'AI_READY_WITH_GAPS' ? 'warn' : 'blocked'
        }
      >
        <header className="corr-completion__head">
          <h2 id="corr-completion-safe-title" className="type-page-title">
            {cs.correlationCompletion.safeTitle}
          </h2>
          <span
            data-testid="correlation-completion-badge"
            data-shareable={shareableWithAi ? 'true' : 'false'}
            data-gate-badge={gateBadge}
          >
            <StatusChip tone={safeTone} label={badge} />
          </span>
        </header>

        <p className="type-meta" data-testid="correlation-completion-honesty">
          {cs.correlationCompletion.honestyNote}
        </p>

        <p className="type-meta" data-testid="correlation-completion-data-count">
          {cs.correlationCompletion.filesExported(dataFiles.length)}
          {companionFiles.length > 0
            ? ` · ${cs.correlationCompletion.companionsExported(companionFiles.length)}`
            : ''}
        </p>

        <ul className="corr-completion__files" data-testid="correlation-completion-data-files">
          {dataFiles.map((name) => (
            <li key={name} className="corr-completion__file-row">
              <IconCheck className="corr-completion__check corr-completion__check--ok" aria-hidden="true" />
              <span>{name}</span>
            </li>
          ))}
        </ul>

        {companionFiles.length > 0 ? (
          <ul className="corr-completion__files" data-testid="correlation-completion-companions">
            {companionFiles.map((name) => (
              <li key={name} className="corr-completion__file-row">
                <IconCheck className="corr-completion__check corr-completion__check--ok" aria-hidden="true" />
                <span>{name}</span>
              </li>
            ))}
          </ul>
        ) : null}

        {skippedFiles.length > 0 ? (
          <div data-testid="correlation-completion-skipped">
            <h3 className="type-section-title">{cs.correlationCompletion.skippedHeading}</h3>
            <ul className="corr-completion__files">
              {skippedFiles.map((f) => (
                <li key={`${f.inputFileName}->${f.outputFileName}`} className="corr-completion__file-row">
                  <IconX className="corr-completion__check corr-completion__check--warn" aria-hidden="true" />
                  <span>
                    {f.inputFileName} → {f.outputFileName}
                  </span>
                  <span className="corr-completion__note type-meta">{f.reason}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {bundleOmitted.length > 0 ? (
          <div data-testid="correlation-completion-bundle-omitted">
            <h3 className="type-section-title">{cs.correlationCompletion.bundleOmittedHeading}</h3>
            <ul className="corr-completion__files">
              {bundleOmitted.map((o) => (
                <li key={o.safeAlias} className="corr-completion__file-row">
                  <IconX className="corr-completion__check corr-completion__check--warn" aria-hidden="true" />
                  <span>{o.safeAlias}</span>
                  <span className="corr-completion__note type-meta">
                    {cs.correlationCompletion.bundleOmittedReason(o.reason)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {completion.partial ? (
          <p className="corr-completion__note type-meta" role="status">
            {cs.correlationCompletion.partialNote}
          </p>
        ) : null}
        {completion.exposedIncluded ? (
          <p className="corr-completion__note corr-completion__note--warn type-meta" role="status">
            {cs.correlationCompletion.exposedNote}
          </p>
        ) : null}
        {downloadUnverified ? (
          <p
            className="corr-completion__note type-meta"
            role="status"
            data-testid="correlation-completion-download-note"
          >
            {cs.correlationCompletion.downloadUnverifiedNote}
          </p>
        ) : null}
      </section>

      <section
        className="corr-completion__block corr-completion__block--private"
        aria-labelledby="corr-completion-private-title"
      >
        <header className="corr-completion__head">
          <h2 id="corr-completion-private-title" className="type-page-title">
            {cs.correlationCompletion.privateTitle}
          </h2>
          <StatusChip tone="warn" label={cs.correlationCompletion.privateBadge} />
        </header>
        <p className="type-meta" data-testid="correlation-completion-map-format">
          {cs.correlationCompletion.privateWarning}
        </p>
        <Button
          variant="secondary"
          data-testid="correlation-completion-bundle-export"
          onClick={() => setBundleOpen(true)}
        >
          {cs.correlationCompletion.exportMapping}
        </Button>
      </section>

      <div className="corr-completion__actions">
        <Button
          variant="secondary"
          data-testid="correlation-completion-back-review"
          onClick={() => enterCorrelationReviewPhase({ preserveSelection: true })}
        >
          {cs.correlationCompletion.backToReview}
        </Button>
        <Button
          variant="primary"
          data-testid="correlation-completion-close-set"
          onClick={() => finishCorrelationSessionAndClear()}
        >
          {cs.correlationCompletion.closeSet}
        </Button>
      </div>

      {bundleOpen ? (
        <MappingBundleExportDialog busy={bundleBusy} onCancel={closeBundle} onConfirm={() => void runBundleExport()} />
      ) : null}
    </section>
  )
}
