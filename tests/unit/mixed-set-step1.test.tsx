/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CorrelationWorkspace } from '../../src/features/correlation-workspace/CorrelationWorkspace.tsx'
import { CorrelationStagingView } from '../../src/features/correlation-staging/CorrelationStagingView.tsx'
import { cs } from '../../src/i18n/cs.ts'
import { useAppStore } from '../../src/app/store.ts'
import {
  clearCorrelationSession,
  createTextSourceAdapter,
  enterCorrelationReviewPhase,
  getCorrelationWorkspaceSummary,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import {
  getStagingConfirmBlockedReason,
  resetCorrelationImportForTests,
} from '../../src/correlation/import/correlationImportController.ts'
import { replaceStagingItems } from '../../src/correlation/import/stagingModel.ts'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import type { StagingItem } from '../../src/correlation/import/types'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Step 1 — mixed set shell and staging', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationImportForTests()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    useAppStore.getState().resetSession()
  })

  it('allows the same analysis action with one ready file', () => {
    const items: StagingItem[] = [
      {
        id: 'a',
        file: textFile('a.log', 'x'),
        fileName: 'a.log',
        byteLength: 1,
        status: 'ready',
        kind: SK.Text,
        profileLabel: 'test',
      },
    ]
    replaceStagingItems(items)
    useAppStore.getState().bumpCorrelationEpoch()
    expect(getStagingConfirmBlockedReason()).toBeNull()
    render(<CorrelationStagingView />)
    expect(screen.getByTestId('staging-confirm')).toBeEnabled()
    expect(screen.queryByTestId('staging-blocked-reason')).toBeNull()
    expect(screen.getByTestId('staging-confirm')).toHaveTextContent(cs.correlationStaging.confirmSingle)
  })

  it('opens the first attention source after analysis and focuses problems without identities', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'ok', kind: SK.Text, file: textFile('ok.log', 'host 10.0.0.5\n') },
      { sourceId: 'bad', kind: SK.Text, file: textFile('bad.log', 'plain\n') },
    ])
    await runCorrelationSession()
    // Force a failed state on second source without discovery identities.
    const { getCorrelationSessionModel } = await import('../../src/correlation/correlationSessionModel.ts')
    const model = getCorrelationSessionModel()
    const bad = model?.sources.get('bad')
    if (bad) {
      model!.sources.set('bad', {
        ...bad,
        phase: 'failed',
        exportState: 'blocked',
        errorMessage: 'Syntetická chyba bez identit',
        discovery: undefined,
      })
    }
    enterCorrelationReviewPhase()
    const summary = getCorrelationWorkspaceSummary()
    expect(summary.nextProblemSourceId).toBe('bad')
    expect(useAppStore.getState().selectedCorrelationSourceId).toBe('bad')

    const user = userEvent.setup()
    render(<CorrelationWorkspace />)
    expect(screen.getByTestId('correlation-summary-bar')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-review-next-problem')).toBeInTheDocument()
    await user.click(screen.getByTestId('correlation-review-next-problem'))
    expect(useAppStore.getState().selectedCorrelationSourceId).toBe('bad')
    expect(useAppStore.getState().statusMessage).toMatch(/Syntetická chyba/)
  })

  it('keeps export visible and close set as primary session exit', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'as', kind: SK.Text, file: textFile('as.log', 'host 10.0.0.5\n') },
      { sourceId: 'dot', kind: SK.Text, file: textFile('dot.log', 'client 10.0.0.5\n') },
    ])
    await runCorrelationSession()
    enterCorrelationReviewPhase()
    render(<CorrelationWorkspace />)
    expect(screen.getByRole('heading', { name: cs.correlationWorkspace.title })).toBeInTheDocument()
    expect(screen.getByTestId('correlation-export-open')).toBeVisible()
    expect(screen.getByTestId('correlation-close-session')).toHaveTextContent(cs.correlationWorkspace.close)
    expect(screen.getByTestId('correlation-add-source')).toBeInTheDocument()
  })
})
