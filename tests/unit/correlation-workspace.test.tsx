/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CorrelationWorkspace } from '../../src/features/correlation-workspace/CorrelationWorkspace.tsx'
import { cs } from '../../src/i18n/cs.ts'
import { useAppStore } from '../../src/app/store.ts'
import {
  clearCorrelationSession,
  createTextSourceAdapter,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import {
  buildCorrelationEntityRows,
  getEntityListMode,
  isOriginalRevealed,
} from '../../src/correlation/correlationReviewModel.ts'
import { enterCorrelationReviewPhase } from '../../src/correlation/correlationWorkspaceController.ts'
import * as CorrelationWorkspaceController from '../../src/correlation/correlationWorkspaceController.ts'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Stage 28 correlation workspace UI', () => {
  beforeEach(async () => {
    clearCorrelationSession()
    resetSharedMappingClient()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    useAppStore.getState().resetSession()

    await stageCorrelationDescriptors([
      { sourceId: 'as', kind: SK.Text, file: textFile('as.log', 'host 10.0.0.5 seen\n') },
      { sourceId: 'dot', kind: SK.Text, file: textFile('dot.log', 'client 10.0.0.5 ok\n') },
    ])
    await runCorrelationSession()
    enterCorrelationReviewPhase()
  })

  it('renders workspace with source rail and shared values on overview', async () => {
    const user = userEvent.setup()
    render(<CorrelationWorkspace />)
    expect(screen.getByTestId('correlation-workspace')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: cs.correlationWorkspace.sourcesNav })).toBeInTheDocument()
    await user.click(screen.getByTestId('corr-rail-all'))
    expect(screen.getByTestId('correlation-entity-list')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-toolbar-meta')).toBeInTheDocument()
  })

  it('switches selected source from the rail', async () => {
    const user = userEvent.setup()
    render(<CorrelationWorkspace />)
    const rail = screen.getByRole('navigation', { name: cs.correlationWorkspace.sourcesNav })
    const buttons = rail.querySelectorAll('button')
    const dotButton = [...buttons].find((b) => b.textContent?.includes('dot.log'))
    expect(dotButton).toBeTruthy()
    await user.click(dotButton!)
    expect(useAppStore.getState().selectedCorrelationSourceId).toBe('dot')
  })

  it('shows shared values tab in inspector for text sources', async () => {
    const user = userEvent.setup()
    render(<CorrelationWorkspace />)
    const rail = screen.getByRole('navigation', { name: cs.correlationWorkspace.sourcesNav })
    const asButton = [...rail.querySelectorAll('button')].find((b) => b.textContent?.includes('as.log'))
    expect(asButton).toBeTruthy()
    await user.click(asButton!)
    expect(await screen.findByTestId('review-panel')).toBeInTheDocument()
    expect(screen.getByTestId('review-tab-shared')).toBeInTheDocument()
    await user.click(screen.getByTestId('review-tab-shared'))
    expect(screen.getByTestId('review-shared')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-entity-list')).toBeInTheDocument()
  })

  it('exposes cross-source occurrence navigation in source preview', async () => {
    const user = userEvent.setup()
    render(<CorrelationWorkspace />)
    const rail = screen.getByRole('navigation', { name: cs.correlationWorkspace.sourcesNav })
    const dotButton = [...rail.querySelectorAll('button')].find((b) => b.textContent?.includes('dot.log'))
    expect(dotButton).toBeTruthy()
    await user.click(dotButton!)
    expect(screen.getByTestId('correlation-occurrence-nav')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: cs.correlationWorkspace.prevOccurrence })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: cs.correlationWorkspace.nextOccurrence })).toBeInTheDocument()
  })

  it('offers mapping bundle export during multi-source review', () => {
    render(<CorrelationWorkspace />)
    const exportButton = screen.getByTestId('correlation-workspace-bundle-export')
    expect(exportButton).toBeInTheDocument()
    expect(exportButton).toHaveTextContent(cs.bundle.exportToolbar)
    expect(exportButton).not.toBeDisabled()
    expect(screen.queryByTestId('correlation-map-menu')).not.toBeInTheDocument()
    expect(screen.queryByTestId('mapping-bundle-import-open')).not.toBeInTheDocument()
    expect(screen.getByTestId('correlation-close-session')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-export-open')).toBeInTheDocument()
  })

  it('keeps export CTA visible when no sources are ready', () => {
    render(<CorrelationWorkspace />)
    expect(screen.getByTestId('correlation-export-open')).toBeInTheDocument()
  })

  it('places add-files next to the source switcher', () => {
    render(<CorrelationWorkspace />)
    expect(screen.getByTestId('correlation-add-source')).toBeInTheDocument()
    expect(screen.getByTestId('corr-rail-all')).toHaveTextContent(cs.correlationWorkspace.setOverview)
  })

  it('shows shared entity mapping in overview', async () => {
    const user = userEvent.setup()
    render(<CorrelationWorkspace />)
    await user.click(screen.getByTestId('corr-rail-all'))
    const shared = buildCorrelationEntityRows('shared')
    expect(shared.length).toBeGreaterThan(0)
    const first = shared[0]!
    const card = screen.getByTestId(`corr-entity-${first.key}`)
    expect(card.querySelector('.ui-icon')).toBeTruthy()
    expect(card).toHaveTextContent(first.alias)
    expect(card).toHaveTextContent(first.original)
    expect(card).not.toHaveTextContent('••••')
    expect(card).toHaveTextContent('as.log')
    expect(card).toHaveTextContent('dot.log')
    expect(card.querySelectorAll('.file-kind-badge')).toHaveLength(2)
  })

  it('jumps to the matching source when a shared-value chip is clicked', async () => {
    const user = userEvent.setup()
    const jump = vi
      .spyOn(CorrelationWorkspaceController, 'jumpToCorrelationOccurrence')
      .mockImplementation(() => {})
    render(<CorrelationWorkspace />)
    await user.click(screen.getByTestId('corr-rail-all'))

    const shared = buildCorrelationEntityRows('shared')
    expect(shared.length).toBeGreaterThan(0)
    const first = shared[0]!
    expect(first.sourceIds).toEqual(expect.arrayContaining(['as', 'dot']))

    await user.click(screen.getByTestId(`corr-entity-source-${first.key}--dot`))
    expect(jump).toHaveBeenCalledWith(expect.objectContaining({ sourceId: 'dot' }))

    jump.mockClear()
    await user.click(screen.getByTestId(`corr-entity-source-${first.key}--as`))
    expect(jump).toHaveBeenCalledWith(expect.objectContaining({ sourceId: 'as' }))
    jump.mockRestore()
  })

  it('switches shared entity tabs and toggles original visibility', async () => {
    const user = userEvent.setup()
    render(<CorrelationWorkspace />)
    await user.click(screen.getByTestId('corr-rail-all'))

    const sharedTab = screen.getByTestId('corr-entities-tab-shared')
    const allTab = screen.getByTestId('corr-entities-tab-all')
    const revealToggle = screen.getByTestId('corr-entities-reveal-toggle')

    expect(sharedTab).toHaveAttribute('aria-selected', 'true')
    expect(allTab).toHaveAttribute('aria-selected', 'false')
    expect(getEntityListMode()).toBe('shared')
    expect(isOriginalRevealed()).toBe(true)
    expect(revealToggle).toHaveTextContent(cs.correlationWorkspace.hideOriginal)

    const entityList = () => within(screen.getByTestId('correlation-entity-list'))

    const sharedCount = buildCorrelationEntityRows('shared').length
    const allCount = buildCorrelationEntityRows('all').length
    expect(allCount).toBeGreaterThanOrEqual(sharedCount)
    expect(entityList().getAllByRole('option')).toHaveLength(sharedCount)

    await user.click(allTab)
    expect(allTab).toHaveAttribute('aria-selected', 'true')
    expect(sharedTab).toHaveAttribute('aria-selected', 'false')
    expect(getEntityListMode()).toBe('all')
    expect(entityList().getAllByRole('option')).toHaveLength(allCount)

    await user.click(sharedTab)
    expect(getEntityListMode()).toBe('shared')
    expect(entityList().getAllByRole('option')).toHaveLength(sharedCount)

    const first = buildCorrelationEntityRows('shared')[0]!
    const card = entityList().getByTestId(`corr-entity-${first.key}`)
    expect(card).toHaveTextContent(first.original)

    await user.click(revealToggle)
    await waitFor(() => {
      expect(isOriginalRevealed()).toBe(false)
      expect(screen.getByTestId('corr-entities-reveal-toggle')).toHaveTextContent(cs.correlationWorkspace.showOriginal)
    })
    expect(card).toHaveTextContent('••••')
    expect(card).not.toHaveTextContent(first.original)

    await user.click(screen.getByTestId('corr-entities-reveal-toggle'))
    await waitFor(() => {
      expect(isOriginalRevealed()).toBe(true)
      expect(screen.getByTestId('corr-entities-reveal-toggle')).toHaveTextContent(cs.correlationWorkspace.hideOriginal)
    })
    expect(card).toHaveTextContent(first.original)
  })

  it('shared entity controls work in review panel tab', async () => {
    const user = userEvent.setup()
    render(<CorrelationWorkspace />)
    const rail = screen.getByRole('navigation', { name: cs.correlationWorkspace.sourcesNav })
    const asButton = [...rail.querySelectorAll('button')].find((b) => b.textContent?.includes('as.log'))
    await user.click(asButton!)
    await user.click(screen.getByTestId('review-tab-shared'))

    const allTab = screen.getByTestId('corr-entities-tab-all')
    await user.click(allTab)
    expect(getEntityListMode()).toBe('all')

    const revealToggle = screen.getByTestId('corr-entities-reveal-toggle')
    await user.click(revealToggle)
    await waitFor(() => expect(isOriginalRevealed()).toBe(false))
    await user.click(screen.getByTestId('corr-entities-reveal-toggle'))
    await waitFor(() => expect(isOriginalRevealed()).toBe(true))
  })
})
