/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { CorrelationStagingView } from '../../src/features/correlation-staging/CorrelationStagingView.tsx'
import { useAppStore } from '../../src/app/store.ts'
import { replaceStagingItems, getStagingItems } from '../../src/correlation/import/stagingModel.ts'
import { resetCorrelationImportForTests, getStagingConfirmBlockedReason, confirmCorrelationStaging } from '../../src/correlation/import/correlationImportController.ts'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import type { StagingItemReady } from '../../src/correlation/import/types'
import { CORRELATION_SESSION_LIMITS } from '../../src/domain/capabilityContract'
import { cs } from '../../src/i18n/cs.ts'
import { startPcapSession, startTextSession } from '../../src/app/sessionLifecycleCoordinator'

vi.mock('../../src/app/sessionLifecycleCoordinator', async importOriginal => ({
  ...await importOriginal<typeof import('../../src/app/sessionLifecycleCoordinator')>(),
  startTextSession: vi.fn(async () => {}),
  startPcapSession: vi.fn(async () => {}),
}))

function ready(id: string, kind: StagingItemReady['kind'] = SK.Text): StagingItemReady {
  const file = new File(['host 10.0.0.1\n'], `${id}.${kind === SK.Text ? 'log' : 'pcap'}`)
  return { id, fileName: file.name, kind, status: 'ready', byteLength: file.size, profileLabel: 'default', file }
}

describe('staging uses one analysis action for one or multiple files', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    resetCorrelationImportForTests()
    useAppStore.getState().resetSession()
    useAppStore.getState().setPhase('correlation-staging')
  })

  it.each([SK.Text, SK.Pcap])('routes the remaining %s through the same primary button', async kind => {
    const remaining = ready('keep', kind)
    replaceStagingItems([remaining, ready('remove', kind)])
    render(<CorrelationStagingView />)
    expect(screen.getByTestId('staging-confirm')).toHaveTextContent(cs.correlationStaging.confirm)
    fireEvent.click(screen.getByTestId('staging-remove-remove'))
    expect(screen.queryByTestId('staging-continue-single')).toBeNull()
    expect(screen.queryByTestId('staging-blocked-reason')).toBeNull()
    const confirm = screen.getByTestId('staging-confirm')
    expect(confirm).toBeEnabled()
    expect(confirm).toHaveTextContent(cs.correlationStaging.confirmSingle)
    expect(getStagingConfirmBlockedReason()).toBeNull()
    fireEvent.click(confirm)
    await waitFor(() => {
      expect(kind === SK.Text ? startTextSession : startPcapSession)
        .toHaveBeenCalledWith(kind === SK.Text ? { file: remaining.file } : remaining.file)
    })
    expect(kind === SK.Text ? startPcapSession : startTextSession).not.toHaveBeenCalled()
    expect(getStagingItems()).toHaveLength(0)
  })

  it('disables analysis after removing all files and leaves add-files available', () => {
    replaceStagingItems([ready('last')])
    render(<CorrelationStagingView />)
    fireEvent.click(screen.getByTestId('staging-remove-last'))
    expect(screen.getByTestId('staging-confirm')).toBeDisabled()
    expect(screen.getByTestId('staging-blocked-reason')).toHaveTextContent(cs.correlationStaging.blockedNoReady)
    expect(screen.getByTestId('staging-add-files')).toBeEnabled()
  })

  it('does not bypass aggregate limits with a single ready file', async () => {
    replaceStagingItems([{ ...ready('large'), byteLength: CORRELATION_SESSION_LIMITS.maxAggregateBytes + 1 }])
    render(<CorrelationStagingView />)
    expect(screen.getByTestId('staging-confirm')).toBeDisabled()
    expect(getStagingConfirmBlockedReason()).toBe(cs.correlationStaging.blockedAggregateLimit)
    expect(await confirmCorrelationStaging()).toEqual({ ok: false, message: cs.correlationStaging.blockedAggregateLimit })
    expect(startTextSession).not.toHaveBeenCalled()
  })

  it('locks list actions while starting the single file', async () => {
    let finish!: () => void
    vi.mocked(startPcapSession).mockImplementationOnce(() => new Promise<void>(resolve => { finish = resolve }))
    replaceStagingItems([ready('only', SK.Pcap)])
    render(<CorrelationStagingView />)
    fireEvent.click(screen.getByTestId('staging-confirm'))
    await waitFor(() => expect(startPcapSession).toHaveBeenCalled())
    expect(screen.getByTestId('staging-confirm')).toBeDisabled()
    expect(screen.getByTestId('staging-add-files')).toBeDisabled()
    expect(screen.getByTestId('staging-back')).toBeDisabled()
    finish()
    await waitFor(() => expect(screen.getByTestId('staging-add-files')).toBeEnabled())
  })
})
