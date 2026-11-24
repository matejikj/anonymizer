import { useEffect, useState } from 'react'
import { getCorrelationSource } from '../../correlation/correlationSessionModel.ts'
import { mountCorrelationTextSession } from '../../correlation/mountCorrelationTextSession.ts'
import { materializeTextFileForReview } from '../../correlation/textMaterialization.ts'
import { getSourceScroll } from '../../correlation/correlationReviewModel.ts'
import {
  beginSourceMount,
  defaultTextSourceUi,
  getTextSourceUi,
  isSourceMountCurrent,
  makeSourceMountToken,
  rememberTextSourceUi,
} from '../../correlation/correlationSourceUiContext.ts'
import { DualLogView } from '../workspace/DualLogView.tsx'
import { getDualLogBridge } from '../workspace/editorBridge.ts'
import { WorkspaceCommandStrip, OversizedLineBanner } from '../workspace/WorkspaceCommandStrip.tsx'
import { ReviewPanel } from '../review/ReviewPanel.tsx'
import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import type { TextSourcePlan } from '../../correlation/types.ts'

export interface CorrelationTextReviewProps {
  readonly sourceId: string
}

/**
 * Full text editor chrome inside a mixed set — DualLogView + ReviewPanel + local strip
 * without close/export. SessionModel is the preview slot; toggles publish into the
 * correlation source plan via reviewActions → publishCorrelationTextReviewFromSession.
 */
export function CorrelationTextReview({ sourceId }: CorrelationTextReviewProps) {
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [mountGen, setMountGen] = useState(0)
  const correlationEpoch = useAppStore((s) => s.correlationEpoch)
  const savedUi = getTextSourceUi(sourceId)

  useEffect(() => {
    let cancelled = false
    let unmountSession: (() => void) | null = null
    const record = getCorrelationSource(sourceId)
    if (!record || record.plan?.kind !== 'text' || record.discovery?.kind !== 'text') {
      setError(cs.correlationWorkspace.textUnavailable)
      setLoading(false)
      return
    }
    setError(null)
    setLoading(true)
    const plan = record.plan as TextSourcePlan
    const token = makeSourceMountToken(sourceId, plan.generationId)
    beginSourceMount(token)

    // Restore Inspector / occurrence chrome before the session mounts.
    const ui = getTextSourceUi(sourceId) ?? defaultTextSourceUi()
    const store = useAppStore.getState()
    store.setOccurrenceIndex(ui.occurrenceIndex)
    store.setFocusedLine(ui.focusedLine)
    store.setReviewTab(ui.reviewTab)
    store.setEntityFilter(ui.entityFilter)
    store.setEntityQuery(ui.entityQuery)
    store.setWrapEnabled(ui.wrapEnabled)

    void (async () => {
      try {
        const materialized = await materializeTextFileForReview(sourceId, record.file)
        if (cancelled || !isSourceMountCurrent(token)) return
        const latest = getCorrelationSource(sourceId)
        if (!latest || latest.plan?.kind !== 'text' || latest.discovery?.kind !== 'text') {
          if (!cancelled) {
            setError(cs.correlationWorkspace.textUnavailable)
            setLoading(false)
          }
          return
        }
        unmountSession = mountCorrelationTextSession({
          text: materialized.text,
          discovery: latest.discovery,
          plan: latest.plan,
          textReview: latest.textReview,
          mountToken: token,
        })
        if (!unmountSession) {
          if (!cancelled) {
            setError(cs.correlationWorkspace.textUnavailable)
            setLoading(false)
          }
          return
        }
        if (!cancelled) {
          setMountGen((n) => n + 1)
          setLoading(false)
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : cs.correlationWorkspace.textUnavailable)
          setLoading(false)
        }
      }
    })()

    return () => {
      cancelled = true
      const storeState = useAppStore.getState()
      rememberTextSourceUi(sourceId, {
        originalQuery: getTextSourceUi(sourceId)?.originalQuery ?? '',
        originalCase: getTextSourceUi(sourceId)?.originalCase ?? false,
        anonQuery: getTextSourceUi(sourceId)?.anonQuery ?? '',
        anonCase: getTextSourceUi(sourceId)?.anonCase ?? false,
        occurrenceIndex: storeState.occurrenceIndex,
        focusedLine: storeState.focusedLine,
        reviewTab: storeState.reviewTab,
        entityFilter: storeState.entityFilter,
        entityQuery: storeState.entityQuery,
        wrapEnabled: storeState.wrapEnabled,
      })
      unmountSession?.()
    }
  }, [sourceId])

  useEffect(() => {
    if (loading) return
    const scroll = getSourceScroll(sourceId)
    if (!scroll?.line) return
    const targetLine = scroll.line
    let raf = 0
    let cancelled = false
    let appliedTo: ReturnType<typeof getDualLogBridge> = null
    let settleFrames = 0
    const tick = () => {
      if (cancelled) return
      const bridge = getDualLogBridge()
      if (bridge && bridge !== appliedTo) {
        bridge.highlightLine(targetLine)
        appliedTo = bridge
        settleFrames = 0
      } else if (appliedTo) {
        settleFrames += 1
      }
      if (!appliedTo || settleFrames < 10) raf = requestAnimationFrame(tick)
    }
    tick()
    return () => {
      cancelled = true
      if (raf) cancelAnimationFrame(raf)
    }
  }, [sourceId, loading, correlationEpoch, mountGen])

  if (error) return <p role="alert">{error}</p>

  return (
    <div className="corr-text-review" data-testid="correlation-text-review" data-source-id={sourceId}>
      {loading ? <p className="corr-text-review__loading">{cs.correlationWorkspace.loadingText}</p> : null}
      {!loading ? (
        <>
          <WorkspaceCommandStrip variant="correlation" />
          <OversizedLineBanner />
          <div className="workspace__stage">
            <DualLogView
              key={`${sourceId}-${mountGen}`}
              correlationSourceId={sourceId}
              initialSearch={{
                originalQuery: savedUi?.originalQuery ?? '',
                originalCase: savedUi?.originalCase ?? false,
                anonQuery: savedUi?.anonQuery ?? '',
                anonCase: savedUi?.anonCase ?? false,
              }}
              onSearchStateChange={(next) => {
                const prev = getTextSourceUi(sourceId) ?? defaultTextSourceUi()
                rememberTextSourceUi(sourceId, { ...prev, ...next })
              }}
            />
            <ReviewPanel correlationSourceId={sourceId} />
          </div>
        </>
      ) : null}
    </div>
  )
}
