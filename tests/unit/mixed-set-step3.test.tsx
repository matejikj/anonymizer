/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { CorrelationWorkspace } from '../../src/features/correlation-workspace/CorrelationWorkspace.tsx'
import { CorrelationTextReview } from '../../src/features/correlation-workspace/CorrelationTextReview.tsx'
import { useAppStore } from '../../src/app/store.ts'
import {
  clearCorrelationSession,
  createTextSourceAdapter,
  enterCorrelationReviewPhase,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { resetCorrelationWorkspaceForTests } from '../../src/correlation/correlationWorkspaceController.ts'
import { selectCorrelationSource } from '../../src/correlation/correlationReviewModel.ts'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('DESIGN_MOVES step 3 — mixed-set single set chrome', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationWorkspaceForTests()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    useAppStore.getState().resetSession()
  })

  it('keeps set identity, rail, add, and set exports in one chrome row', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 't1', kind: SK.Text, file: textFile('a.log', 'host 10.0.0.5\n') },
      { sourceId: 't2', kind: SK.Text, file: textFile('b.log', 'peer 10.0.0.6\n') },
    ])
    await runCorrelationSession()
    enterCorrelationReviewPhase()
    useAppStore.getState().setStatusMessage('Připraveno 2 soubory ke kontrole.')

    render(<CorrelationWorkspace />)
    const chrome = screen.getByTestId('correlation-set-chrome')
    expect(chrome).toHaveClass('corr-workspace__chrome--set')
    const row = screen.getByTestId('correlation-set-row')
    expect(chrome.contains(row)).toBe(true)
    expect(row).toHaveClass('workspace-chrome')
    expect(row.contains(screen.getByTestId('correlation-toolbar-meta'))).toBe(true)
    expect(row.contains(screen.getByTestId('correlation-source-rail'))).toBe(true)
    expect(row.contains(screen.getByTestId('correlation-add-source'))).toBe(true)
    expect(row.contains(screen.getByTestId('correlation-toolbar-actions'))).toBe(true)
    expect(row.contains(screen.getByTestId('correlation-export-open'))).toBe(true)
    expect(row.contains(screen.getByTestId('correlation-workspace-bundle-export'))).toBe(true)
    expect(screen.queryByTestId('correlation-source-bar')).toBeNull()
    // Idle ready status is not a second bar — meta already carries readiness.
    expect(screen.queryByTestId('correlation-summary-bar')).toBeNull()
  })

  it('embeds text file chrome without a second export identity', async () => {
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
    const fileChrome = screen.getByTestId('correlation-text-toolbar')
    expect(fileChrome).toHaveClass('workspace-chrome--embedded')
    expect(screen.queryByTestId('close-log')).toBeNull()
    expect(screen.queryByTestId('export-bar')).toBeNull()
    expect(fileChrome.querySelector('.ds-command-bar__primary')).toBeNull()
  })

  it('ships CSS for single set row and narrow rail→select swap', () => {
    const css = readFileSync(join(process.cwd(), 'src/styles/corr-workspace.css'), 'utf8')
    expect(css).toMatch(/\.corr-workspace__chrome--set/)
    expect(css).toMatch(/\.corr-workspace__set-row/)
    expect(css).toMatch(/flex-wrap:\s*nowrap/)
    expect(css).toMatch(/@media \(max-width: 900px\)[\s\S]*\.corr-rail-select-wrap[\s\S]*display:\s*block/)
    expect(css).not.toMatch(/\.corr-workspace__source-row\s*\{/)
  })
})
