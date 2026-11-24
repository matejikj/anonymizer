/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TextProgressView } from '../../src/features/import-log/TextProgressView.tsx'
import { cs } from '../../src/i18n/cs.ts'
import { useAppStore } from '../../src/app/store.ts'
import { createIdleProgress, phaseMessage } from '../../src/features/import-log/importProgress.ts'

describe('TextProgressView', () => {
  beforeEach(() => {
    useAppStore.getState().resetSession()
    useAppStore.getState().setImportProgress({
      ...createIdleProgress(),
      phase: 'analyzing',
      message: phaseMessage('analyzing'),
      startedAt: Date.now(),
      fileName: 'sample.log',
      totalBytes: 4096,
      processedBytes: 1024,
      processedLines: 42,
    })
  })

  it('renders splash progress with cancel action', () => {
    render(<TextProgressView />)
    expect(screen.getByTestId('import-progress')).toBeInTheDocument()
    expect(screen.getByText(cs.textProgress.working)).toBeInTheDocument()
    expect(screen.getByText(cs.textProgress.analyzing)).toBeInTheDocument()
    expect(screen.getByText('sample.log')).toBeInTheDocument()
    expect(screen.getByTestId('cancel-analysis')).toBeInTheDocument()
  })
})
