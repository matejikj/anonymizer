/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CorrelationStagingView } from '../../src/features/correlation-staging/CorrelationStagingView.tsx'
import { useAppStore } from '../../src/app/store.ts'
import { replaceStagingItems } from '../../src/correlation/import/stagingModel.ts'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { cs } from '../../src/i18n/cs.ts'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Sprint UX-3 staging single-file hint', () => {
  beforeEach(() => {
    useAppStore.getState().resetSession()
    useAppStore.getState().setPhase('correlation-staging')
  })

  it('offers continue with one ready file', () => {
    replaceStagingItems([
      {
        id: 'only',
        fileName: 'solo.log',
        kind: SK.Text,
        status: 'ready',
        byteLength: 12,
        profileLabel: 'default',
        file: textFile('solo.log', 'line\n'),
      },
    ])
    useAppStore.getState().bumpCorrelationEpoch()

    render(<CorrelationStagingView />)
    expect(screen.getByTestId('staging-single-file-hint')).toBeInTheDocument()
    expect(screen.getByTestId('staging-continue-single')).toHaveTextContent(cs.correlationStaging.continueSingle)
    expect(screen.getByTestId('staging-confirm')).toBeDisabled()
  })
})
