/**
 * @vitest-environment happy-dom
 */
import { describe, expect, it, beforeEach } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import { usePcapStore } from '../../../src/pcap/ui/pcapStore'
import { clearPcapSession, resolveAnonymizedCounterpart } from '../../../src/pcap/ui/pcapSession'
import { PcapComparisonWorkspace } from '../../../src/pcap/ui/PcapComparisonWorkspace'
import { PcapDataViewBar } from '../../../src/pcap/ui/PcapDataViewBar'
import { mapFieldCounterpart, highlightRangeForPane } from '../../../src/pcap/ui/fieldCounterpartMapping'
import { topVisiblePacketIndex, scrollTopForPacketIndex, scrollTopForRelatedPacket } from '../../../src/pcap/ui/pcapScrollSync'
import { withViewMappedEndpoints } from '../../../src/pcap/ui/viewFilterContext'
import { buildCreateColoringRuleOptions } from '../../../src/pcap/ui/createColoringRuleFrom'
import type { PacketFilterContext } from '../../../src/pcap/displayFilter'
import type { DissectionNode } from '../../../src/pcap/dissection/types'
import { PCAP_DUAL_PANE_MIN_WIDTH, layoutFromWorkspaceWidth } from '../../../src/pcap/ui/pcapCompareLayout'

describe('PCAP side-by-side completion gaps', () => {
  beforeEach(() => {
    clearPcapSession()
    usePcapStore.getState().resetToEmpty()
    usePcapStore.setState({
      compareLayout: 'dual',
      layoutMode: 'desktop',
      focusedPane: 'anonymized',
      dataView: 'anonymized',
      panelSizesLinked: true,
      filteredIndicesOriginal: [0, 1, 2, 3],
      filteredIndicesAnonymized: [0, 2, 3],
      filteredIndices: [0, 2, 3],
      selectedPacketIndex: 0,
      workspaceWidth: 1600,
      scrollTopOriginal: 0,
      scrollTopAnonymized: 0,
    })
  })

  it('preserves selection/filter/scroll anchors across dual → single → dual', () => {
    usePcapStore.setState({
      selectedPacketIndex: 2,
      selectedFieldPath: 'frame/eth',
      selectedByteOffset: 12,
      displayFilterApplied: 'udp',
      scrollTopOriginal: 56,
      scrollTopAnonymized: 28,
      compareRatio: 0.45,
    })
    usePcapStore.getState().setCompareLayout('single')
    expect(usePcapStore.getState().selectedPacketIndex).toBe(2)
    expect(usePcapStore.getState().selectedFieldPath).toBe('frame/eth')
    expect(usePcapStore.getState().selectedByteOffset).toBe(12)
    expect(usePcapStore.getState().displayFilterApplied).toBe('udp')
    expect(usePcapStore.getState().scrollTopOriginal).toBe(56)
    expect(usePcapStore.getState().scrollTopAnonymized).toBe(28)
    usePcapStore.getState().setDataView('original')
    expect(usePcapStore.getState().focusedPane).toBe('original')
    usePcapStore.getState().setCompareLayout('dual')
    expect(usePcapStore.getState().selectedPacketIndex).toBe(2)
    expect(usePcapStore.getState().compareRatio).toBe(0.45)
    expect(usePcapStore.getState().scrollTopOriginal).toBe(56)
  })

  it('maps field counterpart and reports unmapped without false match', () => {
    const roots: DissectionNode[] = [
      {
        id: 'frame',
        label: 'Frame',
        offset: 0,
        length: 42,
        children: [
          { id: 'eth', label: 'Ethernet', offset: 0, length: 14, children: [] },
          { id: 'gen', label: 'Generated', offset: 0, length: 0, generated: true, children: [] },
        ],
      },
    ]
    expect(
      mapFieldCounterpart({
        fieldPath: 'frame/eth',
        byteOffset: 0,
        counterpartRoots: roots,
      }).kind,
    ).toBe('mapped')
    expect(
      mapFieldCounterpart({
        fieldPath: 'frame/missing',
        byteOffset: 0,
        counterpartRoots: roots,
      }),
    ).toMatchObject({ kind: 'unmapped', reason: 'missing-path' })
    expect(
      mapFieldCounterpart({
        fieldPath: 'frame/gen',
        byteOffset: 0,
        counterpartRoots: roots,
      }),
    ).toMatchObject({ kind: 'unmapped', reason: 'generated' })
    expect(
      highlightRangeForPane({
        fieldPath: 'frame/missing',
        byteOffset: 0,
        roots,
      }),
    ).toBe('unmapped')
  })

  it('syncs scroll by packet anchor not raw scrollTop', () => {
    const indices = [0, 2, 5, 9]
    expect(topVisiblePacketIndex(0, indices)).toBe(0)
    expect(topVisiblePacketIndex(28, indices)).toBe(2)
    expect(topVisiblePacketIndex(56, indices)).toBe(5)
    expect(scrollTopForPacketIndex(5, indices)).toBe(56)
    expect(scrollTopForPacketIndex(1, indices)).toBeNull()
    // Missing packet → insertion-point (next present), not distant abs nearest.
    expect(scrollTopForRelatedPacket(1, indices)).toBe(28) // next is 2 at row 1
    expect(scrollTopForRelatedPacket(3, indices)).toBe(56) // next is 5 at row 2
    expect(scrollTopForRelatedPacket(100, indices)).toBe(84) // clamp to last row
  })

  it('gate: dual shows both panes; single shows switch', () => {
    expect(layoutFromWorkspaceWidth(PCAP_DUAL_PANE_MIN_WIDTH)).toBe('dual')
    render(<PcapComparisonWorkspace />)
    expect(screen.getByTestId('pcap-data-pane-original')).toBeTruthy()
    expect(screen.getByTestId('pcap-data-pane-anonymized')).toBeTruthy()
    expect(screen.queryByTestId('pcap-data-view-switch')).toBeNull()

    act(() => {
      usePcapStore.setState({ compareLayout: 'single' })
    })
    render(<PcapDataViewBar />)
    expect(screen.getByTestId('pcap-data-view-switch')).toBeTruthy()
  })

  it('builds create-from coloring drafts from filter context', () => {
    const ctx: PacketFilterContext = {
      packetIndex: 0,
      packetNumber: 1,
      capturedLength: 64,
      linkType: 1,
      data: new Uint8Array(0),
      protocols: ['udp', 'sip'],
      changed: false,
      hasIssue: false,
      srcIpv4: '10.0.0.1',
      dstIpv4: '10.0.0.2',
      srcPort: 5060,
      dstPort: 5060,
      l4Proto: 'udp',
    }
    const drafts = buildCreateColoringRuleOptions(ctx, ctx.protocols)
    expect(drafts.some((d) => d.kind === 'protocol')).toBe(true)
    expect(drafts.some((d) => d.kind === 'ip.src')).toBe(true)
    expect(drafts.some((d) => d.filter.includes('udp.port'))).toBe(true)
  })

  it('view-mapped endpoints leave original unchanged without snapshot', () => {
    const ctx: PacketFilterContext = {
      packetIndex: 0,
      packetNumber: 1,
      capturedLength: 64,
      linkType: 1,
      data: new Uint8Array(0),
      protocols: ['udp'],
      changed: false,
      hasIssue: false,
      srcIpv4: '192.168.1.1',
      dstIpv4: '192.168.1.2',
    }
    const mapped = withViewMappedEndpoints(ctx, 'anonymized', null)
    expect(mapped.srcIpv4).toBe('192.168.1.1')
  })

  it('resolves filtered counterpart state', () => {
    expect(resolveAnonymizedCounterpart(-1, [])).toMatchObject({ kind: 'dropped' })
  })
})
