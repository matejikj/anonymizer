/**
 * T21 — NetFlow v5 / IPFIX / sFlow: alias consistency, missing template, sFlow canary.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import {
  __testSeedIpfixTemplate,
  resetFlowExportCachesForMapping,
  resetFlowExportCachesForTests,
  disposeFlowExportCachesForSession,
  sanitizeNetflowV9OrIpfix,
} from '../../../src/pcap/sanitize/flowExport'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { discoverPacket } from '../../../src/pcap/discovery/discoverPacket'

function packetInput(data: Uint8Array, index = 0) {
  return {
    index,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function u16(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff])
}

function u32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff])
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((a, p) => a + p.length, 0)
  const out = new Uint8Array(len)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

describe('T21 registry', () => {
  it('registers handlers and flow-export families', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('netflow-v5')
    expect(ids).toContain('ipfix')
    expect(ids).toContain('sflow')
    expect(familyForProtocol('netflow-v5').familyId).toBe('flow-export')
    expect(familyForProtocol('ipfix').familyId).toBe('flow-export')
    expect(familyForProtocol('sflow').familyId).toBe('flow-export')
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T21 NetFlow v5', () => {
  it('maps flow record IPv4 to the same alias as the outer IP header', () => {
    const canary = [203, 0, 113, 77] as const
    const hdr = concat(
      u16(5), // version
      u16(1), // count
      u32(1000), // sys_uptime
      u32(1_700_000_000), // unix_secs
      u32(0), // unix_nsecs
      u32(1), // flow_sequence
      new Uint8Array([0, 0]), // engine
      u16(0), // sampling
    )
    const rec = new Uint8Array(48)
    rec.set(canary, 0) // srcaddr
    rec.set([10, 0, 0, 2], 4) // dst
    rec.set([10, 0, 0, 1], 8) // nexthop
    rec[32] = 0xc0
    rec[33] = 0x00 // srcport 49152
    rec[34] = 0
    rec[35] = 80 // dstport 80
    rec[38] = 6 // TCP
    const payload = concat(hdr, rec)
    // Outer IP uses same canary as srcaddr
    const frame = buildEthIpUdp([...canary], [10, 0, 0, 2], 2055, 2055, payload)
    const mapping = new SessionMapping(undefined, { seed: 't21-nf5' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'netflow-v5')).toBe(true)
    const out = applyPatches(frame, result)
    // Ethernet(14) + IPv4(20) → src at 26
    const outerAlias = [...out.subarray(26, 30)]
    // UDP header 8 → payload at 42; record src at +24
    const flowAlias = [...out.subarray(42 + 24, 42 + 28)]
    expect(outerAlias).not.toEqual([...canary])
    expect(flowAlias).toEqual(outerAlias)
    // Well-known TCP/80 preserved by port policy
    expect((out[42 + 24 + 34]! << 8) | out[42 + 24 + 35]!).toBe(80)
  })
})

describe('T21 IPFIX', () => {
  it('masks data set when template is missing', () => {
    const canary = new TextEncoder().encode('IPFIX-SECRET')
    // IPFIX hdr + data set without template
    const dataBody = new Uint8Array(16)
    dataBody.set(canary, 0)
    const set = concat(u16(256), u16(4 + dataBody.length), dataBody)
    const msgLen = 16 + set.length
    const hdr = concat(
      u16(10),
      u16(msgLen),
      u32(1_700_000_000),
      u32(1),
      u32(1), // domain
    )
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 4739, 4739, concat(hdr, set))
    const mapping = new SessionMapping(undefined, { seed: 't21-miss' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ipfix-data' && c.status === 'requires-reassembly')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('IPFIX-SECRET')).toBe(false)
  })

  it('maps IPv4 IE when template is known', () => {
    const mapping = new SessionMapping(undefined, { seed: 't21-tmpl' })
    __testSeedIpfixTemplate(
      mapping,
      7,
      256,
      [
        { type: 8, length: 4, enterprise: 0 },
        { type: 12, length: 4, enterprise: 0 },
        { type: 7, length: 2, enterprise: 0 },
        { type: 11, length: 2, enterprise: 0 },
      ],
      { srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 4739, dstPort: 4739 },
    )
    const record = concat(
      new Uint8Array([203, 0, 113, 88]),
      new Uint8Array([10, 1, 2, 3]),
      u16(12345),
      u16(443),
    )
    const set = concat(u16(256), u16(4 + record.length), record)
    const msgLen = 16 + set.length
    const hdr = concat(u16(10), u16(msgLen), u32(1_700_000_000), u32(1), u32(7))
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 4739, 4739, concat(hdr, set))
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ipfix-data' && c.status === 'covered')).toBe(true)
    const out = applyPatches(frame, result)
    const recOff = 42 + 16 + 4
    expect([...out.subarray(recOff, recOff + 4)]).not.toEqual([203, 0, 113, 88])
  })

  it('T21: discovery pass scopes IPFIX templates by generationId (passthrough mapping)', () => {
    resetFlowExportCachesForTests()
    const templateBody = concat(u16(256), u16(1), u16(8), u16(4))
    const templateSet = concat(u16(2), u16(4 + templateBody.length), templateBody)
    const tmplMsgLen = 16 + templateSet.length
    const tmplHdr = concat(u16(10), u16(tmplMsgLen), u32(1_700_000_000), u32(1), u32(7))
    const tmplFrame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 4739, 4739, concat(tmplHdr, templateSet))
    discoverPacket(
      packetInput(tmplFrame, 0),
      0,
      DIAGNOSTIC_POLICY,
      undefined,
      undefined,
      { generationId: 'disc-gen-a', sourceId: 'pcap-x' },
    )

    const record = new Uint8Array([203, 0, 113, 88])
    const dataSet = concat(u16(256), u16(4 + record.length), record)
    const dataMsgLen = 16 + dataSet.length
    const dataHdr = concat(u16(10), u16(dataMsgLen), u32(1_700_000_000), u32(1), u32(7))
    const dataFrame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 4739, 4739, concat(dataHdr, dataSet))
    const pd = discoverPacket(
      packetInput(dataFrame, 1),
      1,
      DIAGNOSTIC_POLICY,
      undefined,
      undefined,
      { generationId: 'disc-gen-b', sourceId: 'pcap-x' },
    )
    expect(pd.issues?.some((i) => i.includes('missing-template'))).toBe(true)
    expect(
      pd.coverage.some((c) => c.protocol === 'ipfix-data' && c.status === 'requires-reassembly'),
    ).toBe(true)
  })

  it('T21: template seeded in generation A is not visible in generation B (same mapping)', () => {
    resetFlowExportCachesForTests()
    const mapping = new SessionMapping(undefined, { seed: 't21-gen-scope' })
    const exporter = { srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 4739, dstPort: 4739 }
    __testSeedIpfixTemplate(
      mapping,
      7,
      256,
      [{ type: 8, length: 4, enterprise: 0 }],
      exporter,
      { generationId: 'gen-a', sourceId: 'pcap-a' },
    )
    const record = new Uint8Array([203, 0, 113, 88])
    const set = concat(u16(256), u16(4 + record.length), record)
    const msgLen = 16 + set.length
    const payload = concat(u16(10), u16(msgLen), u32(1_700_000_000), u32(1), u32(7), set)
    const collector = new PatchCollector(payload.length)
    const result = sanitizeNetflowV9OrIpfix(
      payload,
      0,
      payload.length,
      collector,
      mapping,
      undefined,
      0,
      undefined,
      exporter,
      { generationId: 'gen-b', sourceId: 'pcap-a' },
    )
    expect(result?.issues?.some((i) => i.includes('missing-template'))).toBe(true)
    expect(
      result?.coverage.some((c) => c.protocol === 'ipfix-data' && c.status === 'requires-reassembly'),
    ).toBe(true)
  })

  it('T21: resetFlowExportCachesForMapping clears templates before a remapped generation', () => {
    resetFlowExportCachesForTests()
    const mapping = new SessionMapping(undefined, { seed: 't21-reset' })
    const exporter = { srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 4739, dstPort: 4739 }
    const session = { generationId: 'gen-same', sourceId: 'pcap-1' }
    __testSeedIpfixTemplate(
      mapping,
      7,
      256,
      [{ type: 8, length: 4, enterprise: 0 }],
      exporter,
      session,
    )
    resetFlowExportCachesForMapping(mapping)
    const record = new Uint8Array([203, 0, 113, 88])
    const set = concat(u16(256), u16(4 + record.length), record)
    const msgLen = 16 + set.length
    const payload = concat(u16(10), u16(msgLen), u32(1_700_000_000), u32(1), u32(7), set)
    const collector = new PatchCollector(payload.length)
    const result = sanitizeNetflowV9OrIpfix(
      payload,
      0,
      payload.length,
      collector,
      mapping,
      undefined,
      0,
      undefined,
      exporter,
      session,
    )
    expect(result?.issues?.some((i) => i.includes('missing-template'))).toBe(true)
  })

  it('T21: disposeFlowExportCachesForSession clears templates (session teardown)', () => {
    resetFlowExportCachesForTests()
    const mapping = new SessionMapping(undefined, { seed: 't21-dispose' })
    const exporter = { srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 4739, dstPort: 4739 }
    const session = { generationId: 'gen-dispose', sourceId: 'pcap-1' }
    __testSeedIpfixTemplate(
      mapping,
      7,
      256,
      [{ type: 8, length: 4, enterprise: 0 }],
      exporter,
      session,
    )
    disposeFlowExportCachesForSession()
    const record = new Uint8Array([203, 0, 113, 88])
    const set = concat(u16(256), u16(4 + record.length), record)
    const msgLen = 16 + set.length
    const payload = concat(u16(10), u16(msgLen), u32(1_700_000_000), u32(1), u32(7), set)
    const collector = new PatchCollector(payload.length)
    const result = sanitizeNetflowV9OrIpfix(
      payload,
      0,
      payload.length,
      collector,
      mapping,
      undefined,
      0,
      undefined,
      exporter,
      session,
    )
    expect(result?.issues?.some((i) => i.includes('missing-template'))).toBe(true)
  })

  it('V17: template from exporter A is not reused by exporter B (same domain/template id)', () => {
    const mapping = new SessionMapping(undefined, { seed: 't21-scope' })
    __testSeedIpfixTemplate(
      mapping,
      7,
      256,
      [
        { type: 8, length: 4, enterprise: 0 },
        { type: 12, length: 4, enterprise: 0 },
      ],
      { srcIp: '10.0.0.1', dstIp: '10.0.0.2', srcPort: 4739, dstPort: 4739 },
    )
    const record = concat(new Uint8Array([203, 0, 113, 88]), new Uint8Array([10, 1, 2, 3]))
    const set = concat(u16(256), u16(4 + record.length), record)
    const msgLen = 16 + set.length
    const hdr = concat(u16(10), u16(msgLen), u32(1_700_000_000), u32(1), u32(7))
    // Different exporter source IP — must not hit A's template cache entry.
    const frame = buildEthIpUdp([10, 0, 0, 9], [10, 0, 0, 2], 4739, 4739, concat(hdr, set))
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(
      result.coverage.some((c) => c.protocol === 'ipfix-data' && c.status === 'requires-reassembly'),
    ).toBe(true)
    expect(result.issues.some((i) => i.includes('missing-template'))).toBe(true)
  })
})

describe('T21 sFlow', () => {
  it('maps canary IPv4 inside sampled Ethernet header', () => {
    const canary = [198, 51, 100, 44] as const
    // Minimal IPv4 inside Ethernet
    const ip = new Uint8Array(20)
    ip[0] = 0x45
    ip[3] = 20
    ip[9] = 1
    ip.set(canary, 12)
    ip.set([10, 0, 0, 9], 16)
    const eth = new Uint8Array(14 + ip.length)
    eth.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01], 0)
    eth.set([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 6)
    eth[12] = 0x08
    eth[13] = 0x00
    eth.set(ip, 14)

    const sampledHeader = concat(
      u32(1), // ethernet
      u32(eth.length + 4), // frame_length
      u32(4), // stripped
      u32(eth.length),
      eth,
    )
    // pad to 4
    const pad = (4 - (sampledHeader.length % 4)) % 4
    const headerRec = concat(sampledHeader, new Uint8Array(pad))

    const flowBody = concat(
      u32(1), // seq
      u32(0), // source_id
      u32(1), // sampling_rate
      u32(1), // sample_pool
      u32(0), // drops
      u32(0), // input
      u32(0), // output
      u32(1), // record_count
      u32((0 << 12) | 1), // sampled_header
      u32(headerRec.length),
      headerRec,
    )
    const sample = concat(u32((0 << 12) | 1), u32(flowBody.length), flowBody)

    const datagram = concat(
      u32(5), // version
      u32(1), // IPv4 agent
      new Uint8Array([10, 9, 8, 7]),
      u32(1), // sub_agent
      u32(1), // seq
      u32(1000), // uptime
      u32(1), // num_samples
      sample,
    )
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 6343, 6343, datagram)
    const mapping = new SessionMapping(undefined, { seed: 't21-sflow' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'sflow')).toBe(true)
    const out = applyPatches(frame, result)
    const hay = out
    let found = false
    for (let i = 0; i + 4 <= hay.length; i++) {
      if (
        hay[i] === canary[0]
        && hay[i + 1] === canary[1]
        && hay[i + 2] === canary[2]
        && hay[i + 3] === canary[3]
      ) {
        found = true
        break
      }
    }
    expect(found).toBe(false)
    const agentOff = 42 + 8
    expect([...out.subarray(agentOff, agentOff + 4)]).not.toEqual([10, 9, 8, 7])
  })
})
