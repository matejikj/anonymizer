import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { coverageStatusLabel } from '../../src/pcap/coverage/statusLabels.ts'
import { detectResourceConflict } from '../../src/pcap/ui/pcapResourceCoordinator.ts'
import {
  promptResourceConflict,
  resolveResourceConflict,
  cancelResourceConflict,
} from '../../src/app/resourceConflictPrompt.ts'
import { useAppStore } from '../../src/app/store.ts'
import { usePcapStore } from '../../src/pcap/ui/pcapStore.ts'
import { cs } from '../../src/i18n/cs.ts'
import { startPcapExport } from '../../src/pcap/ui/pcapExportController.ts'
import * as coordinator from '../../src/pcap/export/coordinator'
import { createTestPcapSessionFromPackets } from '../pcap/unit/pcapSessionTestHelpers.ts'
import { createPresetProfile } from '../../src/pcap/profile/presets.ts'

function makeEthIpPacket(src: number[], dst: number[], n: number): import('../../src/pcap/domain/types').PacketEnvelope {
  const data = new Uint8Array(42)
  data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data[16] = 0
  data[17] = 28
  data[23] = 17
  data.set(src, 26)
  data.set(dst, 30)
  return {
    packetNumber: n,
    timestamp: { ticks: BigInt(1700000000 + n) * 1_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('Stage 14 — UX, accessibility, mode consistency', () => {
  beforeEach(() => {
    useAppStore.setState({ resourceConflict: null })
    usePcapStore.setState({ exportBusy: false })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('maps all coverage statuses to Czech labels', () => {
    const statuses = [
      'covered',
      'unsupported',
      'truncated',
      'requires-reassembly',
      'malformed',
      'encrypted',
      'heuristic',
    ] as const
    for (const status of statuses) {
      const label = coverageStatusLabel(status)
      expect(label).not.toBe(status)
      expect(label.length).toBeGreaterThan(0)
    }
  })

  it('detectResourceConflict returns kind only (no window.confirm message)', () => {
    const conflict = detectResourceConflict('pcap', 999)
    expect(conflict).toBeNull()
    if (conflict) {
      expect(conflict).toEqual({ kind: expect.any(String) })
      expect('message' in conflict).toBe(false)
    }
  })

  it('promptResourceConflict resolves via accessible dialog store', async () => {
    const promise = promptResourceConflict({ kind: 'pcap-over-text' })
    expect(useAppStore.getState().resourceConflict?.kind).toBe('pcap-over-text')
    resolveResourceConflict(true)
    await expect(promise).resolves.toBe(true)
    expect(useAppStore.getState().resourceConflict).toBeNull()
  })

  it('cancelResourceConflict rejects the pending prompt', async () => {
    const promise = promptResourceConflict({ kind: 'text-over-pcap' })
    cancelResourceConflict()
    await expect(promise).resolves.toBe(false)
  })

  it('startPcapExport runs immediately with no confirmation dialog', async () => {
    const runSpy = vi.spyOn(coordinator, 'runPcapExport').mockResolvedValue({
      fileName: 'out.pcap',
      byteLength: 100,
      reportFileName: 'out.report.json',
      reportJson: '{}',
      usedFileSystemAccess: false,
      partialFilePossible: false,
    })

    const packets = [makeEthIpPacket([192, 168, 1, 1], [10, 0, 0, 1], 1)]
    await createTestPcapSessionFromPackets({
      fileName: 'diag.pcap',
      packets,
      profile: createPresetProfile('diagnostic', { id: 'test-diag', name: 'Test' }),
    })

    await startPcapExport()
    expect(runSpy).toHaveBeenCalledTimes(1)
    runSpy.mockRestore()
  })

  it('i18n includes status disclaimers and copy-block explanation', () => {
    expect(cs.security.statusDisclaimer).toMatch(/certifikaci/i)
    expect(cs.pcap.status.statusDisclaimer).toMatch(/certifikaci/i)
    expect(cs.workspace.largeLogCopyBlocked).toMatch(/export/i)
    expect(cs.pcap.workspace.narrowHint).toMatch(/úzké|900|širší/i)
    expect(cs.workspace.oversizedLines).not.toMatch(/zkrácený/i)
  })
})
