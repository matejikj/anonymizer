/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { CorrelationWorkspace } from '../../src/features/correlation-workspace/CorrelationWorkspace.tsx'
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
import { getCorrelationSource } from '../../src/correlation'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('DESIGN_MOVES step 8 — workspace alert stack', () => {
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

  it('mounts a single alert stack above the data plane', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 't1', kind: SK.Text, file: textFile('a.log', 'host 10.0.0.5\n') },
      { sourceId: 't2', kind: SK.Text, file: textFile('b.log', 'peer 10.0.0.6\n') },
    ])
    await runCorrelationSession()
    enterCorrelationReviewPhase()
    useAppStore.getState().setPlanBusy(true)

    render(<CorrelationWorkspace />)
    const stack = screen.getByTestId('workspace-alert-stack')
    expect(stack).toBeInTheDocument()
    expect(stack).toHaveClass('workspace-alert-stack')
    const rebuild = screen.getByTestId('correlation-rebuild-banner')
    expect(stack.contains(rebuild)).toBe(true)
    expect(rebuild).toHaveClass('workspace-alert', 'workspace-alert--warn')
    expect(document.querySelector('.corr-rebuild-banner')).toBeNull()
    expect(document.querySelector('.corr-add-progress')).toBeNull()
    expect(document.querySelector('.corr-summary')).toBeNull()
  })

  it('keeps problem summary inside the stack with shared warn language', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'ok', kind: SK.Text, file: textFile('ok.log', 'host 10.0.0.5\n') },
      { sourceId: 'bad', kind: SK.Text, file: textFile('bad.log', 'plain\n') },
    ])
    await runCorrelationSession()
    const bad = getCorrelationSource('bad')
    if (bad) {
      Object.assign(bad, {
        phase: 'failed',
        exportState: 'blocked',
        failureReason: 'Syntetická chyba',
        discovery: undefined,
      })
    }
    enterCorrelationReviewPhase()

    render(<CorrelationWorkspace />)
    const stack = screen.getByTestId('workspace-alert-stack')
    const summary = screen.getByTestId('correlation-summary-bar')
    expect(stack.contains(summary)).toBe(true)
    expect(summary).toHaveClass('workspace-alert--warn')
  })

  it('ships shared alert CSS and drops legacy corr alert card rules', () => {
    const layout = readFileSync(join(process.cwd(), 'src/styles/workspace-layout.css'), 'utf8')
    expect(layout).toContain('.workspace-alert-stack')
    expect(layout).toContain('.workspace-alert--warn')
    expect(layout).toContain('.workspace-alert--ok')
    expect(layout).toContain('.workspace-alert--info')
    const corr = readFileSync(join(process.cwd(), 'src/styles/corr-workspace.css'), 'utf8')
    const staging = readFileSync(join(process.cwd(), 'src/styles/staging.css'), 'utf8')
    const features = readFileSync(join(process.cwd(), 'src/styles/features.css'), 'utf8')
    const joined = `${corr}\n${staging}\n${features}`
    expect(joined).not.toMatch(/^\.corr-rebuild-banner\s*\{/m)
    expect(joined).not.toMatch(/^\.corr-add-progress\s*,/m)
    expect(joined).not.toMatch(/^\.corr-summary\s*\{/m)
  })
})
