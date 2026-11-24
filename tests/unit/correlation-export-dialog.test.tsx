/** @vitest-environment jsdom */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CorrelationExportDialog } from '../../src/features/correlation-workspace/CorrelationExportDialog.tsx'
import { useAppStore } from '../../src/app/store.ts'
import {
  clearCorrelationSession,
  createTextSourceAdapter,
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
import { beforeEach } from 'vitest'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

describe('Step 3 CorrelationExportDialog', () => {
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
      { sourceId: 'a', kind: SK.Text, file: textFile('as-server.log', 'host 10.0.0.5\n') },
      { sourceId: 'b', kind: SK.Text, file: textFile('dot.log', 'client 10.0.0.5\n') },
    ])
    await runCorrelationSession()
  })

  it('lists input→output for all sources and defaults to download destination', async () => {
    const user = userEvent.setup()
    let exported: {
      scope: string
      partial: boolean
      preferDirectoryPicker: boolean
    } | null = null
    render(
      <CorrelationExportDialog
        multiDownloadWarning
        canPickDirectory
        currentSourceId="a"
        onCancel={() => {}}
        onExport={(input) => {
          exported = {
            scope: input.scope,
            partial: input.partial,
            preferDirectoryPicker: input.preferDirectoryPicker,
          }
        }}
      />,
    )
    expect(screen.getByTestId('correlation-export-dialog')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-export-scope-set')).toBeInTheDocument()
    expect(screen.getByTestId('correlation-export-scope-current')).toBeEnabled()
    expect(screen.getByTestId('correlation-export-dest-download')).toBeChecked()

    await user.click(screen.getByTestId('correlation-export-confirm'))
    expect(exported?.scope).toBe('set')
    expect(exported?.partial).toBe(false)
    expect(exported?.preferDirectoryPicker).toBe(false)
  })

  it('switches to current-file scope and can choose directory destination', async () => {
    const user = userEvent.setup()
    let exported: { scope: string; preferDirectoryPicker: boolean } | null = null
    render(
      <CorrelationExportDialog
        multiDownloadWarning={false}
        canPickDirectory
        currentSourceId="a"
        onCancel={() => {}}
        onExport={(input) => {
          exported = {
            scope: input.scope,
            preferDirectoryPicker: input.preferDirectoryPicker,
          }
        }}
      />,
    )
    await user.click(screen.getByTestId('correlation-export-scope-current'))
    await user.click(screen.getByTestId('correlation-export-dest-directory'))
    await user.click(screen.getByTestId('correlation-export-confirm'))
    expect(exported?.scope).toBe('current')
    expect(exported?.preferDirectoryPicker).toBe(true)
  })

  it('disables directory destination when picker is unavailable', () => {
    render(
      <CorrelationExportDialog
        multiDownloadWarning
        canPickDirectory={false}
        currentSourceId="a"
        onCancel={() => {}}
        onExport={() => {}}
      />,
    )
    expect(screen.getByTestId('correlation-export-dest-directory')).toBeDisabled()
    expect(screen.getByTestId('correlation-export-dest-download')).toBeChecked()
  })
})
