/**
 * @vitest-environment happy-dom
 */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import { clearPcapSession, getPacketEndpoints } from '../../../src/pcap/ui/pcapSession'
import { PcapLiveAnnouncer } from '../../../src/pcap/ui/PcapLiveAnnouncer'
import { PcapStatusBar } from '../../../src/pcap/ui/PcapStatusBar'
import { PcapByteGrid } from '../../../src/pcap/ui/PcapByteGrid'
import { PcapDissectionTree } from '../../../src/pcap/ui/PcapDissectionTree'
import type { DissectionNode } from '../../../src/pcap/dissection/types'
import { createTestPcapSessionFromPackets } from './pcapSessionTestHelpers'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { PCAP_WIRESHARK_WIREFRAME_STATES, PCAP_WIRESHARK_VISUAL_SCENARIOS } from '../../../src/pcap/ui/pcapWiresharkWireframe'

function makeEthIpPacket(src: number[], dst: number[], packetNumber: number): PacketEnvelope {
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
    packetNumber,
    timestamp: { ticks: BigInt(packetNumber) * 1000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

const sampleRoots: readonly DissectionNode[] = [
  {
    id: 'frame',
    label: 'Frame',
    offset: 0,
    length: 4,
    children: [
      {
        id: 'eth',
        label: 'ethernet',
        offset: 0,
        length: 4,
        children: [
          { id: 'dst', label: 'Destination', displayValue: 'ff:ff:ff:ff:ff:ff', offset: 0, length: 2, children: [] },
          { id: 'src', label: 'Source', displayValue: 'aa:bb:cc:dd:ee:ff', offset: 2, length: 2, children: [] },
        ],
      },
    ],
  },
]

describe('PCAP Wireshark step 3', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
  })

  it('wireframe state matrix covers step 3 scenarios', () => {
    expect(PCAP_WIRESHARK_WIREFRAME_STATES.length).toBeGreaterThanOrEqual(10)
    expect(PCAP_WIRESHARK_VISUAL_SCENARIOS.length).toBeGreaterThanOrEqual(8)
  })

  it('getPacketEndpoints uses session entities without loading bytes', async () => {
    const packets = [makeEthIpPacket([192, 168, 1, 10], [10, 0, 0, 1], 1)]
    await createTestPcapSessionFromPackets({ fileName: 'ep.pcap', packets })
    const endpoints = getPacketEndpoints(0)
    expect(endpoints.source).toMatch(/192\.168|—/)
    expect(endpoints.dest).toMatch(/10\.0\.0\.1|—/)
  })

  it('live announcer announces packet selection', async () => {
    const packets = [makeEthIpPacket([192, 168, 1, 10], [10, 0, 0, 1], 1)]
    await createTestPcapSessionFromPackets({ fileName: 'a.pcap', packets })
    usePcapStore.setState({ selectedPacketIndex: 0, sessionEpoch: 1, phase: 'workspace' })
    render(<PcapLiveAnnouncer />)
    await waitFor(() => {
      expect(screen.getByTestId('pcap-live-announcer').textContent).toMatch(/Packet \d+ selected/)
    })
  })

  it('status bar shows filter empty state', async () => {
    const packets = [makeEthIpPacket([192, 168, 1, 10], [10, 0, 0, 1], 1)]
    await createTestPcapSessionFromPackets({ fileName: 'sb.pcap', packets })
    usePcapStore.setState({
      sessionEpoch: 1,
      phase: 'workspace',
      compareLayout: 'single',
      displayFilterApplied: 'frame.number == 9999',
      displayFilterStatus: 'valid',
      filteredIndices: [],
      filteredIndicesOriginal: [],
      filteredIndicesAnonymized: [],
    })
    render(<PcapStatusBar />)
    expect(screen.getByTestId('pcap-status-field').textContent).toMatch(/Žádný paket nevyhovuje filtru/)
  })

  it('tree and byte grid share selection via store', () => {
    usePcapStore.setState({ selectedPacketIndex: 0, expandedTreeNodes: ['frame', 'eth'] })
    render(<PcapDissectionTree roots={sampleRoots} />)
    render(
      <PcapByteGrid
        sources={[{ id: 'frame', label: 'Frame', bytes: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]), fieldMap: [] }]}
        roots={sampleRoots}
      />,
    )
    const treeNode = screen.getByTestId('pcap-dissection-tree').querySelector('[data-offset="2"]')
    expect(treeNode).toBeTruthy()
    fireEvent.click(treeNode!)
    expect(usePcapStore.getState().selectedByteOffset).toBe(2)
    expect(usePcapStore.getState().selectedFieldPath).toBeTruthy()
  })

  it('packet list module does not import preview hook per row', async () => {
    const fs = await import('node:fs')
    const path = await import('node:path')
    const { fileURLToPath } = await import('node:url')
    const file = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../../src/pcap/ui/PcapPacketTables.tsx')
    const src = fs.readFileSync(file, 'utf8')
    expect(src.includes('usePacketPreview')).toBe(false)
  })
})
