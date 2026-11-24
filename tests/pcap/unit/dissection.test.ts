import { describe, expect, it, beforeAll } from 'vitest'
import { initProtocols } from '../../../src/pcap/protocols/init'
import { buildPacketDissection } from '../../../src/pcap/dissection/buildPacketDissection'
import { findDeepestNodeAtOffset, flattenDissection } from '../../../src/pcap/dissection/types'

describe('buildPacketDissection', () => {
  beforeAll(() => {
    initProtocols()
  })
  it('builds frame tree with link and network layers', () => {
    const data = new Uint8Array(42)
    data.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    data.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
    data[12] = 0x08
    data[13] = 0x00
    data[14] = 0x45
    data[16] = 0
    data[17] = 28
    data[23] = 17
    data.set([192, 168, 1, 10], 26)
    data.set([10, 0, 0, 1], 30)

    const dissection = buildPacketDissection({
      data,
      linkType: 1,
      packetIndex: 0,
      capturedLength: data.length,
      unifiedSpans: [],
    })

    expect(dissection.roots.length).toBe(1)
    expect(dissection.roots[0]!.label).toBe('Frame')
    expect(dissection.roots[0]!.children.length).toBeGreaterThan(0)
    expect(dissection.sources[0]!.bytes.length).toBe(42)

    const flat = flattenDissection(dissection.roots)
    expect(flat.length).toBeGreaterThan(3)

    const ethNode = flat.find((n) => n.label === 'ethernet' || n.fieldName === 'ethernet')
    if (ethNode) {
      const atMac = findDeepestNodeAtOffset(flat, 0)
      expect(atMac).not.toBeNull()
    }
  })
})
