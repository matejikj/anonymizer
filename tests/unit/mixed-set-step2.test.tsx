/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { CorrelationWorkspace } from '../../src/features/correlation-workspace/CorrelationWorkspace.tsx'
import { CorrelationTextReview } from '../../src/features/correlation-workspace/CorrelationTextReview.tsx'
import { cs } from '../../src/i18n/cs.ts'
import { useAppStore } from '../../src/app/store.ts'
import {
  clearCorrelationSession,
  createTextSourceAdapter,
  enterCorrelationReviewPhase,
  getCorrelationSource,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import { publishCorrelationTextReviewFromSession } from '../../src/correlation/publishCorrelationTextReview.ts'
import { mountCorrelationTextSession } from '../../src/correlation/mountCorrelationTextSession.ts'
import { materializeTextFileForReview } from '../../src/correlation/textMaterialization.ts'
import { actionToggleEntity } from '../../src/features/review/reviewActions.ts'
import { getSessionModel } from '../../src/features/workspace/sessionModel.ts'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { resetCorrelationWorkspaceForTests } from '../../src/correlation/correlationWorkspaceController.ts'
import {
  getTextSourceUi,
  rememberTextSourceUi,
  defaultTextSourceUi,
  resetCorrelationSourceUiContext,
} from '../../src/correlation/correlationSourceUiContext.ts'
import { selectCorrelationSource } from '../../src/correlation/correlationReviewModel.ts'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Step 2 — mixed set editors and plan sync', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationWorkspaceForTests()
    resetCorrelationSourceUiContext()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    useAppStore.getState().resetSession()
  })

  it('publishes Inspector toggles into the correlation source plan and restores on remount', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 't1', kind: SK.Text, file: textFile('a.log', 'host 10.0.0.5\n') },
      { sourceId: 't2', kind: SK.Text, file: textFile('b.log', 'peer 10.0.0.5\n') },
    ])
    await runCorrelationSession()
    enterCorrelationReviewPhase()
    selectCorrelationSource('t1')

    const record = getCorrelationSource('t1')
    expect(record?.plan?.kind).toBe('text')
    expect(record?.discovery?.kind).toBe('text')
    if (!record || record.plan?.kind !== 'text' || record.discovery?.kind !== 'text') {
      throw new Error('expected text plan')
    }

    const mat = await materializeTextFileForReview('t1', record.file)
    mountCorrelationTextSession({
      text: mat.text,
      discovery: record.discovery,
      plan: record.plan,
      textReview: record.textReview,
    })

    const session = getSessionModel()
    expect(session).toBeTruthy()
    const entity = session!.entities[0]
    expect(entity).toBeTruthy()

    useAppStore.getState().setPhase('correlation-review')
    useAppStore.getState().setSelectedCorrelationSourceId('t1')
    actionToggleEntity(entity!.key, false)

    // notifyPlanChanged is async for correlation — call publish directly for determinism
    publishCorrelationTextReviewFromSession('t1')

    const published = getCorrelationSource('t1')
    expect(published?.textReview?.entityEnabled[entity!.key]).toBe(false)
    expect(published?.plan?.kind).toBe('text')
    expect(published?.textReview).toBeTruthy()

    // Remount restores toggles
    mountCorrelationTextSession({
      text: mat.text,
      discovery: published!.discovery as typeof record.discovery,
      plan: published!.plan as typeof record.plan,
      textReview: published!.textReview,
    })
    const remounted = getSessionModel()
    expect(remounted?.entities.find((e) => e.key === entity!.key)?.enabled).toBe(false)
  })

  it('keeps per-source text UI context across switches', () => {
    rememberTextSourceUi('a', defaultTextSourceUi({ originalQuery: 'alpha', occurrenceIndex: 2 }))
    rememberTextSourceUi('b', defaultTextSourceUi({ originalQuery: 'beta', occurrenceIndex: 0 }))
    expect(getTextSourceUi('a')?.originalQuery).toBe('alpha')
    expect(getTextSourceUi('b')?.originalQuery).toBe('beta')
    expect(getTextSourceUi('a')?.occurrenceIndex).toBe(2)
  })

  it('embeds text strip without close/export and labels in-file findings', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 't1', kind: SK.Text, file: textFile('a.log', 'host 10.0.0.5\n') },
      { sourceId: 't2', kind: SK.Text, file: textFile('b.log', 'peer 10.0.0.6\n') },
    ])
    await runCorrelationSession()
    enterCorrelationReviewPhase()
    selectCorrelationSource('t1')
    useAppStore.getState().setPhase('correlation-review')

    render(<CorrelationTextReview sourceId="t1" />)
    await waitFor(() => {
      expect(screen.getByTestId('correlation-text-toolbar')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('close-log')).toBeNull()
    expect(screen.getByText(cs.workspace.findingsInFile)).toBeInTheDocument()
    expect(screen.queryByTestId('text-set-scope-hint')).toBeNull()
    expect(screen.queryByTestId('review-effect-hint')).toBeNull()
  })

  it('labels cross-file occurrence nav distinctly from in-file findings', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 't1', kind: SK.Text, file: textFile('a.log', 'host 10.0.0.5\n') },
      { sourceId: 't2', kind: SK.Text, file: textFile('b.log', 'peer 10.0.0.5\n') },
    ])
    await runCorrelationSession()
    enterCorrelationReviewPhase()
    selectCorrelationSource('t1')
    useAppStore.getState().setPhase('correlation-review')

    render(<CorrelationWorkspace />)
    const nav = screen.getByTestId('correlation-occurrence-nav')
    expect(nav).toHaveAttribute('aria-label', cs.correlationWorkspace.acrossFilesNav)
  })
})
