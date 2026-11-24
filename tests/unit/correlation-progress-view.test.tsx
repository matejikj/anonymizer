/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CorrelationProgressView } from '../../src/features/correlation-workspace/CorrelationProgressView.tsx'
import { cs } from '../../src/i18n/cs.ts'
import {
  initCorrelationProgress,
  markCorrelationSourceActive,
  resetCorrelationProgress,
} from '../../src/correlation/correlationProgressModel'
import {
  clearCorrelationSessionModel,
  createCorrelationSessionModel,
} from '../../src/correlation/correlationSessionModel'
import { buildStagedSourceRecord } from '../../src/correlation/correlationSession'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { useAppStore } from '../../src/app/store.ts'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Stage 28 correlation progress view', () => {
  beforeEach(() => {
    resetCorrelationProgress()
    clearCorrelationSessionModel()
    useAppStore.getState().resetSession()
    createCorrelationSessionModel({
      sessionId: 's1',
      generationId: 'g1',
      descriptors: [{ sourceId: 'a', kind: SK.Text, file: textFile('a.log', 'x\n') }],
      buildRecord: buildStagedSourceRecord,
    })
    initCorrelationProgress(cs.correlationProgress.lead)
    markCorrelationSourceActive('a')
  })

  it('renders splash progress, tips, and cancel action', () => {
    render(<CorrelationProgressView />)
    expect(screen.getByTestId('correlation-progress')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: cs.correlationProgress.title })).toBeInTheDocument()
    expect(screen.getByText(cs.correlationProgress.working)).toBeInTheDocument()
    expect(screen.getByTestId('corr-cancel-processing')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-progress-sources')).toBeInTheDocument()
  })
})
