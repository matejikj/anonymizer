/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CorrelationCompletionView } from '../../src/features/correlation-workspace/CorrelationCompletionView.tsx'
import { cs } from '../../src/i18n/cs.ts'
import {
  markCorrelationExportComplete,
  resetCorrelationExportForTests,
} from '../../src/correlation/export/correlationExportModel'
import { useAppStore } from '../../src/app/store'
import { vi } from 'vitest'

vi.mock('../../src/correlation/correlationWorkspaceController.ts', async () => {
  const actual = await vi.importActual<typeof import('../../src/correlation/correlationWorkspaceController.ts')>(
    '../../src/correlation/correlationWorkspaceController.ts',
  )
  return {
    ...actual,
    enterCorrelationReviewPhase: vi.fn(),
    finishCorrelationSessionAndClear: vi.fn(),
  }
})

import {
  enterCorrelationReviewPhase,
  finishCorrelationSessionAndClear,
} from '../../src/correlation/correlationWorkspaceController.ts'

describe('Step 3 CorrelationCompletionView', () => {
  beforeEach(() => {
    resetCorrelationExportForTests()
    useAppStore.getState().resetSession()
    vi.mocked(enterCorrelationReviewPhase).mockClear()
    vi.mocked(finishCorrelationSessionAndClear).mockClear()
  })

  it('shows only back-to-review and close-set, and suppresses AI badge when partial/exposed', async () => {
    markCorrelationExportComplete({
      exportedFiles: ['a.anonym.log', 'correlation-manifest.json'],
      dataFiles: ['a.anonym.log'],
      companionFiles: ['correlation-manifest.json'],
      skippedFiles: [{ inputFileName: 'b.log', outputFileName: 'b.anonym.log', reason: 'failed' }],
      manifestExported: true,
      partial: true,
      exposedIncluded: true,
      shareableWithAi: false,
      gateBadge: 'NOT_AI_READY',
      usedDirectoryPicker: false,
      downloadUnverified: true,
    })

    const user = userEvent.setup()
    render(<CorrelationCompletionView />)

    expect(screen.getByTestId('correlation-completion-badge')).toHaveAttribute('data-shareable', 'false')
    expect(screen.getByTestId('correlation-completion-badge')).toHaveAttribute(
      'data-gate-badge',
      'NOT_AI_READY',
    )
    expect(screen.getByTestId('correlation-completion-badge')).toHaveTextContent(
      cs.correlationCompletion.partialBadge,
    )
    expect(screen.getByTestId('correlation-completion-honesty')).toHaveTextContent(
      cs.correlationCompletion.honestyNote,
    )
    expect(screen.queryByTestId('correlation-completion-finish')).toBeNull()
    expect(screen.queryByTestId('correlation-completion-resolve')).toBeNull()
    expect(screen.queryByTestId('correlation-completion-clear')).toBeNull()
    expect(screen.getByTestId('correlation-completion-map-format')).toHaveTextContent(
      cs.correlationCompletion.privateWarning,
    )
    expect(screen.getByTestId('correlation-completion-skipped')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-completion-download-note')).toBeInTheDocument()

    await user.click(screen.getByTestId('correlation-completion-back-review'))
    expect(enterCorrelationReviewPhase).toHaveBeenCalledWith({ preserveSelection: true })

    await user.click(screen.getByTestId('correlation-completion-close-set'))
    expect(finishCorrelationSessionAndClear).toHaveBeenCalled()
  })

  it('shows AI shareable badge only for clean full exports', () => {
    markCorrelationExportComplete({
      exportedFiles: ['a.anonym.log'],
      dataFiles: ['a.anonym.log'],
      companionFiles: [],
      skippedFiles: [],
      manifestExported: false,
      partial: false,
      exposedIncluded: false,
      shareableWithAi: true,
      gateBadge: 'AI_READY',
      usedDirectoryPicker: true,
      downloadUnverified: false,
    })
    render(<CorrelationCompletionView />)
    expect(screen.getByTestId('correlation-completion-badge')).toHaveAttribute('data-shareable', 'true')
    expect(screen.getByTestId('correlation-completion-badge')).toHaveAttribute('data-gate-badge', 'AI_READY')
    expect(screen.getByTestId('correlation-completion-badge')).toHaveTextContent(
      cs.correlationCompletion.aiReadyBadge,
    )
    expect(screen.getByTestId('correlation-completion-view').querySelector('.corr-completion__block--ok')).toBeTruthy()
    expect(screen.getByTestId('correlation-completion-view').querySelector('.corr-completion__zone')).toBeNull()
  })
})
