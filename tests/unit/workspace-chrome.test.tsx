/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { createElement } from 'react'
import { PcapMainToolbar } from '../../src/pcap/ui/PcapMainToolbar.tsx'
import { WorkspaceCommandStrip } from '../../src/features/workspace/WorkspaceCommandStrip.tsx'
import { useAppStore } from '../../src/app/store.ts'
import {
  buildSessionModel,
  clearSessionModel,
} from '../../src/features/workspace/sessionModel.ts'
import { analyze } from '../../src/engine/analyze.ts'
import {
  toTransferableBuffers,
  packResolvedMatches,
  entityKeyToIndex,
} from '../../src/engine/packedMatchIndex.ts'

vi.mock('../../src/features/review/SecuritySummaryBar.tsx', () => ({
  SecuritySummaryBar: () => createElement('div', { 'data-testid': 'security-summary' }),
}))

vi.mock('../../src/features/export-log/ExportBar.tsx', () => ({
  ExportBar: () => createElement('div', { 'data-testid': 'export-bar' }),
}))

function mountTextSession(fileName = 'demo.log') {
  const text = 'host 10.0.0.5\n'
  const result = analyze(text)
  const packed = packResolvedMatches(
    result.matches,
    entityKeyToIndex(result.entities),
    () => true,
  )
  const { buffers } = toTransferableBuffers(packed)
  buildSessionModel({
    text,
    detection: {
      requestId: 'wc-test',
      packedMatches: buffers,
      entities: result.entitySummaries,
      lineCount: result.lineCount,
      failedRuleIds: [],
    },
    fileName,
    byteLength: text.length,
    mode: 'common',
  })
  useAppStore.getState().bumpSessionEpoch()
}

describe('WorkspaceChrome contract (DESIGN_MOVES step 2)', () => {
  beforeEach(() => {
    clearSessionModel()
    useAppStore.getState().resetSession()
  })

  it('text standalone chrome exposes context tools status primary slots', () => {
    mountTextSession()
    useAppStore.getState().setPhase('review')

    render(<WorkspaceCommandStrip />)
    const bar = screen.getByTestId('workspace-toolbar')
    expect(bar).toHaveClass('workspace-chrome')
    expect(bar).toHaveAttribute('data-mode', 'standalone')
    expect(screen.getByTestId('close-log')).toBeInTheDocument()
    expect(screen.getByTestId('export-bar')).toBeInTheDocument()
    expect(screen.getByTestId('security-summary')).toBeInTheDocument()
    expect(bar.querySelector('.ds-command-bar__context')).toBeTruthy()
    expect(bar.querySelector('.ds-command-bar__tools')).toBeTruthy()
    expect(bar.querySelector('.ds-command-bar__status')).toBeTruthy()
    expect(bar.querySelector('.ds-command-bar__primary')).toBeTruthy()
  })

  it('text embedded chrome omits close and export', () => {
    mountTextSession()
    useAppStore.getState().setPhase('correlation-review')

    render(<WorkspaceCommandStrip variant="correlation" />)
    const bar = screen.getByTestId('correlation-text-toolbar')
    expect(bar).toHaveClass('workspace-chrome--embedded')
    expect(bar).toHaveAttribute('data-mode', 'embedded')
    expect(screen.queryByTestId('close-log')).toBeNull()
    expect(screen.queryByTestId('export-bar')).toBeNull()
    expect(bar.querySelector('.ds-command-bar__primary')).toBeNull()
  })

  it('PCAP standalone chrome has open/export; embedded is tools-only', () => {
    const { rerender } = render(
      <PcapMainToolbar
        fileName="cap.pcap"
        onOpenFile={() => undefined}
        onExport={() => undefined}
        canExport
        exportLabel="Export"
        mode="standalone"
      />,
    )
    const standalone = screen.getByTestId('pcap-main-toolbar')
    expect(standalone).toHaveClass('workspace-chrome')
    expect(standalone).toHaveAttribute('data-mode', 'standalone')
    expect(screen.getByTestId('pcap-toolbar-open')).toBeInTheDocument()
    expect(screen.getByTestId('pcap-export')).toBeInTheDocument()
    expect(standalone.querySelector('.ds-command-bar__primary')).toBeTruthy()

    rerender(
      <PcapMainToolbar
        fileName="cap.pcap"
        onOpenFile={() => undefined}
        onExport={() => undefined}
        canExport
        exportLabel="Export"
        mode="embedded"
      />,
    )
    const embedded = screen.getByTestId('pcap-main-toolbar')
    expect(embedded).toHaveClass('workspace-chrome--embedded')
    expect(embedded).toHaveAttribute('data-mode', 'embedded')
    expect(screen.queryByTestId('pcap-toolbar-open')).toBeNull()
    expect(screen.queryByTestId('pcap-export')).toBeNull()
    expect(embedded.querySelector('.ds-command-bar__primary')).toBeNull()
    expect(embedded.querySelector('.ds-command-bar__tools')).toBeTruthy()
  })
})
