/**
 * MappingResolveWorkspace — mapping-bundle lookup workspace (Stage 30, redesigned).
 * Two steps under the hood (pick bundle → lookup), but the common path (landing panel picks
 * a file directly) never shows the intermediate step — this component just renders whichever
 * one applies right now.
 */

import { useId, useRef, useSyncExternalStore } from 'react'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'
import {
  getResolveReturnError,
  getResolveReturnStep,
  isResolveReturnBusy,
  selectResolveReturnBundle,
} from './resolveReturnController.ts'
import { disposeActiveSession } from '../../app/sessionLifecycleCoordinator.ts'
import { getResolveOnlySnapshot, subscribeResolveOnlyModel } from './resolveOnlyModel.ts'
import { MappingBundleBrowser } from './MappingBundleBrowser.tsx'
import { AiReportPanel } from './AiReportPanel.tsx'
import { Button } from '../../design-system/index.ts'
import { IconFile } from '../../components/ui/icons.tsx'

export function MappingResolveWorkspace() {
  const resolveOnlyEpoch = useAppStore((s) => s.resolveOnlyEpoch)
  void resolveOnlyEpoch
  const error = getResolveReturnError()
  const busy = isResolveReturnBusy()
  // `payload` is the tearing-safe source of truth for "is a bundle loaded" (see
  // resolveOnlyModel.ts) — deriving the step from it directly, rather than from a second,
  // independent plain-getter call, avoids observing the wizard step and the payload at two
  // different points in time in the same render.
  const { payload, meta } = useSyncExternalStore(subscribeResolveOnlyModel, getResolveOnlySnapshot)
  const step = payload ? 'lookup' : getResolveReturnStep()

  return (
    <section className="mapping-resolve" data-testid="mapping-resolve-workspace" aria-labelledby="mapping-resolve-title">
      <header className="mapping-resolve__header">
        <div className="mapping-resolve__header-main">
          <h1 id="mapping-resolve-title" className="type-page-title">
            {cs.resolveReturn.title}
          </h1>
        </div>
        <div className="mapping-resolve__header-actions">
          <Button variant="secondary" data-testid="resolve-return-close" onClick={() => disposeActiveSession()}>
            {cs.resolveReturn.closeClear}
          </Button>
        </div>
      </header>

      {step === 'pick-bundle' ? <PickBundleStep busy={busy} error={error} /> : null}
      {step === 'lookup' && payload && meta ? (
        <div className="mapping-resolve__lookup" data-testid="resolve-return-lookup">
          <p className="mapping-resolve__meta type-meta">
            <IconFile size={16} aria-hidden="true" />
            <span className="mapping-resolve__meta-file">{meta.fileName}</span>
            <span className="mapping-resolve__meta-sep" aria-hidden="true">
              ·
            </span>
            <span>
              {cs.resolveReturn.metaSummary
                .replace('{entries}', String(meta.entryCount))
                .replace('{sources}', String(meta.sourceCount))}
            </span>
            <span className="mapping-resolve__meta-sep" aria-hidden="true">
              ·
            </span>
            <span className="mapping-resolve__privacy">{cs.resolveReturn.privacyNote}</span>
          </p>

          <MappingBundleBrowser payload={payload} />
          <AiReportPanel bundlePayload={payload} />
        </div>
      ) : null}
    </section>
  )
}

function PickBundleStep(props: { busy: boolean; error: string | null }) {
  const fileRef = useRef<HTMLInputElement>(null)
  const inputId = useId()

  return (
    <div className="mapping-resolve__card" data-testid="resolve-return-pick">
      <p>{cs.resolveReturn.pickLead}</p>
      <label className="visually-hidden" htmlFor={inputId}>
        {cs.resolveReturn.chooseBundle}
      </label>
      <input
        id={inputId}
        ref={fileRef}
        type="file"
        accept=".rnd-mapping-bundle.json,application/json"
        className="visually-hidden"
        disabled={props.busy}
        data-testid="resolve-return-file-input"
        onChange={(e) => {
          const file = e.target.files?.[0]
          e.target.value = ''
          if (file) void selectResolveReturnBundle(file)
        }}
      />
      <Button
        variant="primary"
        data-testid="resolve-return-choose-file"
        disabled={props.busy}
        busy={props.busy}
        onClick={() => fileRef.current?.click()}
      >
        {props.busy ? cs.bundle.importing : cs.resolveReturn.chooseBundle}
      </Button>
      {props.error ? (
        <p className="form-error" role="alert" data-testid="resolve-return-error">
          {props.error}
        </p>
      ) : null}
    </div>
  )
}
