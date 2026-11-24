/**
 * PF-14: getPcapCoverageViewModel must memoize on the session's plan revision instead of
 * rebuilding on every call — it is read from 8+ UI components that re-render on every
 * selection/scroll change.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest'
import * as coverageViewModelModule from '../../src/pcap/coverage/pcapCoverageViewModel'
import { getPcapCoverageViewModel } from '../../src/pcap/ui/getPcapCoverageViewModel'
import { clearPcapSession, getPcapSession, updateSessionPlan } from '../../src/pcap/ui/pcapSession'
import { type PacketEnvelope } from '../../src/pcap/domain/types'
import { createTestPcapSessionFromPackets } from '../pcap/unit/pcapSessionTestHelpers'

function makePacket(n: number): PacketEnvelope {
  const data = new Uint8Array(42)
  data[12] = 0x08
  data[13] = 0x00
  data[14] = 0x45
  data.set([10, 0, 0, 1], 26)
  data.set([10, 0, 0, 2], 30)
  return {
    packetNumber: n,
    timestamp: { ticks: BigInt(n), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('PF-14: getPcapCoverageViewModel memoization', () => {
  beforeEach(() => {
    clearPcapSession()
    vi.restoreAllMocks()
  })

  it('returns null without a session and does not call the builder', () => {
    const spy = vi.spyOn(coverageViewModelModule, 'buildPcapCoverageViewModel')
    expect(getPcapCoverageViewModel()).toBeNull()
    expect(spy).not.toHaveBeenCalled()
  })

  it('does not rebuild across repeated calls with an unchanged plan revision, but does after a revision bump', async () => {
    const packets = [makePacket(1), makePacket(2), makePacket(3)]
    await createTestPcapSessionFromPackets({ fileName: 'memo.pcap', packets })

    const spy = vi.spyOn(coverageViewModelModule, 'buildPcapCoverageViewModel')

    // Simulates 8 components reading the view model for the same render/scroll tick.
    const first = getPcapCoverageViewModel()
    for (let i = 0; i < 20; i++) getPcapCoverageViewModel()
    expect(spy).toHaveBeenCalledTimes(1)
    expect(getPcapCoverageViewModel()).toBe(first) // same cached object identity

    // A real plan change (mapping revision bump, as updateSessionPlan does on profile/mapping
    // updates) must invalidate the cache and produce a fresh model.
    const session = getPcapSession()!
    updateSessionPlan(session.plan, session.profile, session.mappingRevision + 1)
    const second = getPcapCoverageViewModel()
    expect(spy).toHaveBeenCalledTimes(2)
    expect(second).not.toBe(first)

    // Settling back into repeated calls at the new revision must again stop rebuilding.
    for (let i = 0; i < 20; i++) getPcapCoverageViewModel()
    expect(spy).toHaveBeenCalledTimes(2)
  })

  it('rebuilds for a new session (fresh generationId) even if it coincidentally reuses field values', async () => {
    const packets = [makePacket(1)]
    await createTestPcapSessionFromPackets({ fileName: 'a.pcap', packets })
    const spy = vi.spyOn(coverageViewModelModule, 'buildPcapCoverageViewModel')
    const first = getPcapCoverageViewModel()
    expect(spy).toHaveBeenCalledTimes(1)

    clearPcapSession()
    expect(getPcapCoverageViewModel()).toBeNull()

    await createTestPcapSessionFromPackets({ fileName: 'b.pcap', packets })
    const second = getPcapCoverageViewModel()
    expect(spy).toHaveBeenCalledTimes(2)
    expect(second).not.toBe(first)
  })
})
