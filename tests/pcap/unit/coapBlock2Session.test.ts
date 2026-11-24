/**
 * T30 — CoAP Block2 cross-datagram session + option parse.
 */
import { describe, expect, it } from 'vitest'
import {
  CoapBlock2Session,
  parseCoapBlockOption,
} from '../../../src/pcap/sanitize/industrial/coapBlock2Session.ts'
import type { PacketDiscoveryResult } from '../../../src/pcap/discovery/types.ts'

describe('CoAP Block2 option parse', () => {
  it('parses single-byte Block2 (NUM=0 M=0 SZX=0)', () => {
    expect(parseCoapBlockOption(new Uint8Array([0x00]))).toEqual({
      blockNum: 0,
      more: false,
      szx: 0,
    })
  })

  it('parses Block2 with MORE bit set', () => {
    expect(parseCoapBlockOption(new Uint8Array([0x08]))).toEqual({
      blockNum: 0,
      more: true,
      szx: 0,
    })
  })
})

describe('CoAP Block2 session finalize', () => {
  it('marks incomplete multi-datagram transfer requires-reassembly', () => {
    const session = new CoapBlock2Session()
    session.recordSegment('ex', {
      packetIndex: 0,
      blockNum: 0,
      more: true,
      payloadOffset: 10,
      payloadLength: 4,
      blockOptionOffset: 8,
      blockOptionLength: 1,
    })
    const discovery: PacketDiscoveryResult[] = [
      {
        packetIndex: 0,
        packetNumber: 1,
        intents: [],
        coverage: [
          {
            protocol: 'coap-body',
            offset: 10,
            length: 4,
            status: 'requires-reassembly',
          },
        ],
        issues: ['coap-block2-pending'],
        drop: false,
        frozenPlan: {} as PacketDiscoveryResult['frozenPlan'],
        resolvePatches: () => [],
      },
    ]
    session.finalizeDiscovery(discovery)
    expect(discovery[0]!.issues).toContain('coap-block2-incomplete')
    expect(discovery[0]!.coverage[0]!.status).toBe('requires-reassembly')
  })

  it('upgrades coverage when all blocks are present', () => {
    const session = new CoapBlock2Session()
    session.recordSegment('ex', {
      packetIndex: 0,
      blockNum: 0,
      more: true,
      payloadOffset: 10,
      payloadLength: 4,
      blockOptionOffset: 8,
      blockOptionLength: 1,
    })
    session.recordSegment('ex', {
      packetIndex: 1,
      blockNum: 1,
      more: false,
      payloadOffset: 10,
      payloadLength: 4,
      blockOptionOffset: 8,
      blockOptionLength: 1,
    })
    const discovery: PacketDiscoveryResult[] = [
      {
        packetIndex: 0,
        packetNumber: 1,
        intents: [],
        coverage: [
          {
            protocol: 'coap-body',
            offset: 10,
            length: 4,
            status: 'requires-reassembly',
          },
        ],
        issues: ['coap-block2-pending'],
        drop: false,
        frozenPlan: {} as PacketDiscoveryResult['frozenPlan'],
        resolvePatches: () => [],
      },
      {
        packetIndex: 1,
        packetNumber: 2,
        intents: [],
        coverage: [
          {
            protocol: 'coap-body',
            offset: 10,
            length: 4,
            status: 'requires-reassembly',
          },
        ],
        issues: ['coap-block2-pending'],
        drop: false,
        frozenPlan: {} as PacketDiscoveryResult['frozenPlan'],
        resolvePatches: () => [],
      },
    ]
    session.finalizeDiscovery(discovery)
    expect(discovery[0]!.issues).toContain('coap-block2-reassembled')
    expect(discovery[1]!.issues).toContain('coap-block2-reassembled')
    expect(discovery[0]!.coverage[0]!.status).toBe('redacted')
    expect(discovery[1]!.coverage[0]!.status).toBe('redacted')
  })
})
