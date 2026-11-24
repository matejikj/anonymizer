import { describe, expect, it } from 'vitest'
import { buildPacketProtocolIndex, indexedPacketProtocols } from '../../../src/pcap/coverage/packetProtocolIndex'
import type { PacketDiscoveryResult } from '../../../src/pcap/discovery/types'
import { coverageRollupFromDiscovery, ROLLUP_MAX_COVERAGE_KINDS } from '../../../src/pcap/processing/packedCaptureWire'

describe('packed packet protocol membership', () => {
  it('retains structural and sanitizer membership, deduplicates spans, and handles empty packets', () => {
    const discovery: PacketDiscoveryResult[] = [{ packetIndex: 0, packetNumber: 0, drop: false, issues: [], intents: [],
      coverage: ['sip', 'sip', 'sdp', 'dynamic-id-overflow'].map(protocol => ({ protocol, offset: 0, length: 1, status: 'covered' })) }]
    const index = buildPacketProtocolIndex(3, [{ protocols: ['ethernet', 'ipv4', 'udp', 'udp'] },
      { protocols: [] }, { protocols: ['ethernet'] }], discovery, ['sip', 'sdp', 'other'].map(protocol => ({ protocol, status: 'covered' })))
    expect(indexedPacketProtocols(index, 0)).toEqual(['ethernet', 'ipv4', 'udp', 'sip', 'sdp', 'other'])
    expect(indexedPacketProtocols(index, 1)).toEqual([])
    expect(indexedPacketProtocols(index, 2)).toEqual(['ethernet'])
    expect(indexedPacketProtocols(index, -1)).toEqual([])
    expect(indexedPacketProtocols(index, 3)).toEqual([])
    expect(indexedPacketProtocols(undefined, 0)).toEqual([])
    expect(indexedPacketProtocols(buildPacketProtocolIndex(0, [], [], []), 0)).toEqual([])
  })

  it('keeps 235k packets in compact transferable columns without retaining per-span objects', () => {
    const count = 235_000
    const summaries = Array(count).fill({ protocols: ['ethernet', 'ipv4', 'udp', 'sip', 'sip', 'sdp'] })
    const index = buildPacketProtocolIndex(count, summaries, [], [])
    expect(index.offsets.byteLength + index.protocolIds.byteLength).toBeLessThan(6 * 1024 * 1024)
    expect(index.protocols).toHaveLength(5)
    const clone = structuredClone(index, { transfer: [index.offsets.buffer, index.protocolIds.buffer] })
    expect(index.offsets.byteLength).toBe(0)
    expect(indexedPacketProtocols(clone, count - 1)).toEqual(['ethernet', 'ipv4', 'udp', 'sip', 'sdp'])
  })

  it('matches the rollup overflow bucket when a new status of an existing protocol exceeds the cap', () => {
    const discovery: PacketDiscoveryResult[] = Array.from({ length: ROLLUP_MAX_COVERAGE_KINDS + 1 }, (_, i) => ({
      packetIndex: i, packetNumber: i, drop: false, issues: [], intents: [],
      coverage: [{ protocol: `dynamic-${i % ROLLUP_MAX_COVERAGE_KINDS}`, offset: 0, length: 1,
        status: i < ROLLUP_MAX_COVERAGE_KINDS ? 'covered' : 'malformed' }],
    }))
    const rollup = coverageRollupFromDiscovery(discovery)
    const index = buildPacketProtocolIndex(discovery.length, [], discovery, rollup.coverageKinds)
    expect(indexedPacketProtocols(index, 0)).toEqual(['dynamic-0'])
    expect(indexedPacketProtocols(index, ROLLUP_MAX_COVERAGE_KINDS)).toEqual(['other'])
    expect(rollup.protocolSummaries?.find(p => p.protocol === 'other')?.packetCount).toBe(1)
  })
})
