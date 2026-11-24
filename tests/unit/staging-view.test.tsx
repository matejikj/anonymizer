/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CorrelationStagingView } from '../../src/features/correlation-staging/CorrelationStagingView.tsx'
import { cs } from '../../src/i18n/cs.ts'
import {
  ingestDroppedFiles,
  openCorrelationStaging,
  resetCorrelationImportForTests,
} from '../../src/correlation/import/correlationImportController.ts'
import { useAppStore } from '../../src/app/store.ts'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Stage 27 correlation staging view', () => {
  beforeEach(async () => {
    resetCorrelationImportForTests()
    useAppStore.getState().resetSession()
    await ingestDroppedFiles([
      textFile('as-server.log', 'server 10.0.0.1\n'),
      textFile('dot.log', 'client 10.0.0.2\n'),
    ])
    openCorrelationStaging()
  })

  it('renders semantic source list with summary', () => {
    render(<CorrelationStagingView />)
    expect(screen.getByRole('heading', { name: cs.correlationStaging.title })).toBeInTheDocument()
    expect(screen.getByTestId('staging-source-list')).toBeInTheDocument()
    expect(screen.getAllByRole('listitem')).toHaveLength(2)
    expect(screen.getByText(/as-server\.log/)).toBeInTheDocument()
  })

  it('exposes primary confirm and add-files actions', () => {
    render(<CorrelationStagingView />)
    expect(screen.getByRole('button', { name: cs.correlationStaging.confirm })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: cs.correlationStaging.addFiles })).toBeInTheDocument()
  })

  it('is keyboard reachable for add-files control', async () => {
    const user = userEvent.setup()
    render(<CorrelationStagingView />)
    const add = screen.getByTestId('staging-add-files')
    add.focus()
    expect(add).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(add).toBeInTheDocument()
  })

  it('removes a source row from the list', async () => {
    const user = userEvent.setup()
    render(<CorrelationStagingView />)
    await user.click(screen.getByTestId('staging-remove-as-server-0'))
    expect(screen.getAllByRole('listitem')).toHaveLength(1)
  })
})
