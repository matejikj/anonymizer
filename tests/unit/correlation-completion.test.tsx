/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CorrelationCompletionView } from '../../src/features/correlation-workspace/CorrelationCompletionView.tsx'
import { cs } from '../../src/i18n/cs.ts'
import { markCorrelationExportComplete, resetCorrelationExportForTests } from '../../src/correlation/export/correlationExportModel.ts'
import { useAppStore } from '../../src/app/store.ts'

describe('Stage 29 CorrelationCompletionView', () => {
  beforeEach(() => {
    resetCorrelationExportForTests()
    useAppStore.getState().resetSession()
    markCorrelationExportComplete({
      exportedFiles: ['a.anonym.log', 'b.anonym.log'],
      dataFiles: ['a.anonym.log', 'b.anonym.log'],
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
  })

  it('visually separates AI-safe export from private mapping zone', () => {
    render(<CorrelationCompletionView />)
    expect(screen.getByTestId('correlation-completion-view')).toBeInTheDocument()
    expect(screen.getByText(cs.correlationCompletion.safeTitle)).toBeInTheDocument()
    expect(screen.getByText(cs.correlationCompletion.privateTitle)).toBeInTheDocument()
    // Outcome gate + safe-zone badge both show AI READY — assert the intentional badge slot.
    expect(screen.getByTestId('correlation-completion-badge')).toHaveTextContent(
      cs.correlationCompletion.safeForAiBadge,
    )
    expect(screen.getByText(cs.correlationCompletion.privateBadge)).toBeInTheDocument()
    expect(screen.getByTestId('correlation-completion-bundle-export')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-completion-close-set')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-completion-back-review')).toBeInTheDocument()
  })
})
