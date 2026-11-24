/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CorrelationWorkspace } from '../../src/features/correlation-workspace/CorrelationWorkspace.tsx'
import { SourceStagingList } from '../../src/features/correlation-staging/SourceStagingList.tsx'
import { CorrelationExportProgress } from '../../src/features/correlation-workspace/CorrelationExportProgress.tsx'
import { cs } from '../../src/i18n/cs.ts'
import { useAppStore } from '../../src/app/store.ts'
import {
  clearCorrelationSession,
  createTextSourceAdapter,
  enterCorrelationReviewPhase,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  resetCorrelationLiveAnnouncerForTests,
  resetCorrelationUiPhase,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { setCorrelationExportProgress } from '../../src/correlation/export/correlationExportModel'
import type { StagingItem } from '../../src/correlation/import/types'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Stage 31 accessibility UI', () => {
  beforeEach(async () => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationUiPhase()
    resetCorrelationLiveAnnouncerForTests()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    useAppStore.getState().resetSession()

    await stageCorrelationDescriptors([
      { sourceId: 'as', kind: SK.Text, file: textFile('as.log', 'host 10.0.0.5\n') },
      { sourceId: 'dot', kind: SK.Text, file: textFile('dot.log', 'client 10.0.0.5\n') },
    ])
    await runCorrelationSession()
    enterCorrelationReviewPhase()
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
  })

  it('source rail supports arrow key navigation and live region', async () => {
    const user = userEvent.setup()
    render(<CorrelationWorkspace />)
    expect(screen.getByTestId('correlation-source-live')).toBeInTheDocument()
    const rail = screen.getByTestId('correlation-source-rail')
    expect(rail).toHaveAttribute('role', 'listbox')

    const allBtn = screen.getByTestId('corr-rail-all')
    allBtn.focus()
    await user.keyboard('{ArrowDown}')
    expect(useAppStore.getState().selectedCorrelationSourceId).not.toBe('all')
  })

  it('staging status exposes icon and text', () => {
    const items: StagingItem[] = [
      {
        id: 'a',
        fileName: 'a.log',
        kind: SK.Text,
        status: 'ready',
        byteLength: 10,
        profileLabel: 'default',
        file: textFile('a.log', 'x'),
      },
    ]
    render(
      <SourceStagingList
        items={items}
        summary={{
          fileCount: 1,
          readyCount: 1,
          errorCount: 0,
          duplicateCount: 0,
          totalBytes: 10,
          aggregateOverLimit: false,
          aggregateLimitBytes: 1e9,
          bytesToRemove: null,
          largestReadyIds: [],
        }}
        onRemove={() => {}}
      />,
    )
    const status = screen.getByTestId('staging-status-a')
    expect(status.textContent).toContain(cs.correlationStaging.statusTextReady)
    expect(status.querySelector('.status-chip')?.getAttribute('data-status-icon')).toBe('ok')
  })

  it('cancel export progress lists completed and remaining files', () => {
    setCorrelationExportProgress({
      phase: 'cancelled',
      fileIndex: 1,
      fileTotal: 3,
      currentFileName: 'b.anonym.log',
      currentMessage: 'Export zrušen',
      completedFiles: ['a.anonym.log'],
      remainingFiles: ['b.anonym.log', 'c.anonym.log'],
      usedDirectoryPicker: false,
      usedMultiDownloadFallback: true,
    })
    render(<CorrelationExportProgress onCancel={() => {}} />)
    expect(screen.getByTestId('correlation-export-completed')).toBeInTheDocument()
    const remaining = screen.getByTestId('correlation-export-remaining')
    expect(within(remaining).getByText('b.anonym.log')).toBeInTheDocument()
  })
})
