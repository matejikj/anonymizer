/**
 * Step 4 acceptance — export guard rejects when rebuild pending or level mismatch.
 */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { usePcapStore } from '../../src/pcap/ui/pcapStore'
import { clearPcapSession, createMinimalPcapSession } from '../../src/pcap/ui/pcapSession'
import { startPcapExport } from '../../src/pcap/ui/pcapExportController'
import { CaptureFormat } from '../../src/pcap/domain/types'
import * as coordinator from '../../src/pcap/export/coordinator'
import { cs } from '../../src/i18n/cs'

const srcDir = join(dirname(fileURLToPath(import.meta.url)), '../../src')

describe('Step 4 — export level guard', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
  })

  it('rejects export when requestedPcapLevel is pending', () => {
    createMinimalPcapSession({ fileName: 'a.pcap', fileSize: 100, format: CaptureFormat.ClassicPcap })
    usePcapStore.getState().setPhase('workspace')
    usePcapStore.getState().setRequestedPcapLevel('high-privacy')

    const runSpy = vi.spyOn(coordinator, 'runPcapExport').mockResolvedValue({
      fileName: 'out.pcap',
      byteLength: 100,
      reportFileName: 'out.report.json',
      reportJson: '{}',
      usedFileSystemAccess: false,
      partialFilePossible: false,
      recoveryCreated: false,
    })

    startPcapExport()
    expect(runSpy).not.toHaveBeenCalled()
    expect(usePcapStore.getState().exportHint).toBe(cs.pcap.export.rebuildPendingHint)
    runSpy.mockRestore()
  })

  it('rejects export when planStale is true', () => {
    createMinimalPcapSession({ fileName: 'b.pcap', fileSize: 100, format: CaptureFormat.ClassicPcap })
    usePcapStore.getState().setPhase('workspace')
    usePcapStore.getState().setPlanStale(true)

    const runSpy = vi.spyOn(coordinator, 'runPcapExport').mockResolvedValue({
      fileName: 'out.pcap',
      byteLength: 100,
      reportFileName: 'out.report.json',
      reportJson: '{}',
      usedFileSystemAccess: false,
      partialFilePossible: false,
      recoveryCreated: false,
    })

    startPcapExport()
    expect(runSpy).not.toHaveBeenCalled()
    expect(usePcapStore.getState().exportHint).toBe(cs.pcap.export.rebuildPendingHint)
    runSpy.mockRestore()
  })

  it('rejects export when plan pcapLevel does not match active level', () => {
    createMinimalPcapSession({ fileName: 'c.pcap', fileSize: 100, format: CaptureFormat.ClassicPcap })
    usePcapStore.getState().setPhase('workspace')
    // Session profile is diagnostic (default), switch store to high-privacy without rebuild
    usePcapStore.getState().setActivePcapLevel('high-privacy')

    const runSpy = vi.spyOn(coordinator, 'runPcapExport').mockResolvedValue({
      fileName: 'out.pcap',
      byteLength: 100,
      reportFileName: 'out.report.json',
      reportJson: '{}',
      usedFileSystemAccess: false,
      partialFilePossible: false,
      recoveryCreated: false,
    })

    startPcapExport()
    expect(runSpy).not.toHaveBeenCalled()
    expect(usePcapStore.getState().exportHint).toBe(cs.pcap.export.levelMismatchHint)
    runSpy.mockRestore()
  })
})

describe('Step 4 — PCAP select wiring', () => {
  it('PcapAnonymizationLevelSelect rebuilds only when capture is open', () => {
    const src = readFileSync(join(srcDir, 'pcap/ui/PcapAnonymizationLevelSelect.tsx'), 'utf8')
    expect(src).toMatch(/rebuild:\s*hasCapture/)
    expect(src).toMatch(/phase === 'workspace'/)
  })

  it('correlation controller passes text profile for text, pcap profile for pcap', () => {
    const ctrl = readFileSync(join(srcDir, 'correlation/correlationController.ts'), 'utf8')
    expect(ctrl).toMatch(/textProfile/)
    expect(ctrl).toMatch(/getActiveProfile/)
    expect(ctrl).toMatch(/pcapProfile/)
    expect(ctrl).toMatch(/getActivePcapProfile/)
    expect(ctrl).not.toMatch(/pcapProfile.*configSchema/)
    expect(ctrl).not.toMatch(/pcapProfile.*rulesetValidate/)
  })

  it('workerPcapPlanRebuildPort uses generation counter for race safety', () => {
    const src = readFileSync(join(srcDir, 'pcap/profile/workerPcapPlanRebuildPort.ts'), 'utf8')
    expect(src).toMatch(/latestGeneration/)
    expect(src).toMatch(/shouldApply/)
    expect(src).toMatch(/generation === latestGeneration/)
  })
})
