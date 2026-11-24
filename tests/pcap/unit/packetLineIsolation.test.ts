/**
 * T07 — packet isolation (PCAP) and line isolation (text) fail-closed without aborting the file.
 */

import { describe, expect, it, vi } from 'vitest'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY, createPresetProfile } from '../../../src/pcap/profile/presets'
import { discoverPacket } from '../../../src/pcap/discovery/discoverPacket'
import { buildDeterministicPlan } from '../../../src/pcap/plan/deterministicPlanBuilder'
import { buildIsolatedPacketResult } from '../../../src/pcap/sanitize/packetIsolation'
import { IncidentLog } from '../../../src/domain/anonymizationIncident'
import { DetectionSession } from '../../../src/workers/detectionSession'
import { LINE_ISOLATION_DETECTOR_ID } from '../../../src/workers/detectionSession'
import * as detectLine from '../../../src/engine/detectLine'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import { runDiscoveryPipeline, identitiesFromDiscovery } from '../../../src/pcap/discovery/discoveryPipeline'
import { buildCaptureFromPlan } from '../../../src/pcap/export/engine'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { createDefaultRulesetConfig } from '../../../src/domain/configSchema'
import { buildReplacementPlan, transformWithPlan } from '../../../src/engine/transform'
import { packResolvedMatches } from '../../../src/engine/packedMatchIndex'
import { countPhysicalLines } from '../../../src/domain/invariants'
import { applyReassemblyPatchesToResults } from '../../../src/pcap/reassembly/capturePhase'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import * as sipOverReassembled from '../../../src/pcap/reassembly/sipOverReassembled'
import type { ReassemblyContext } from '../../../src/pcap/reassembly/types'
import type { PacketSanitizationResult } from '../../../src/pcap/sanitize/types'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function buildEthIpUdp(
  src: number[],
  dst: number[],
  sport: number,
  dport: number,
  payload: Uint8Array,
): Uint8Array {
  const ipLen = 20 + 8 + payload.length
  const out = new Uint8Array(14 + ipLen)
  // eth
  out.set([0x02, 0, 0, 0, 0, 1], 0)
  out.set([0x02, 0, 0, 0, 0, 2], 6)
  out[12] = 0x08
  out[13] = 0x00
  const ip = 14
  out[ip] = 0x45
  out[ip + 2] = (ipLen >> 8) & 0xff
  out[ip + 3] = ipLen & 0xff
  out[ip + 8] = 64
  out[ip + 9] = 17
  out.set(src, ip + 12)
  out.set(dst, ip + 16)
  const udp = ip + 20
  out[udp] = (sport >> 8) & 0xff
  out[udp + 1] = sport & 0xff
  out[udp + 2] = (dport >> 8) & 0xff
  out[udp + 3] = dport & 0xff
  const ulen = 8 + payload.length
  out[udp + 4] = (ulen >> 8) & 0xff
  out[udp + 5] = ulen & 0xff
  out.set(payload, udp + 8)
  return out
}

function envelope(data: Uint8Array, index: number): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('T07 packet isolation', () => {
  it('buildIsolatedPacketResult masks payload under diagnostic and drops under high-privacy', () => {
    const data = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 12345, 5060, latin1('INVITE sip:x'))
    const diag = buildIsolatedPacketResult({
      packetIndex: 0,
      capturedLength: data.length,
      linkType: 1,
      data,
      policy: DIAGNOSTIC_POLICY,
      unit: 'packet',
      reason: 'sanitizer-exception',
      safePrefixEnd: 14,
    })
    expect(diag.drop).toBe(false)
    expect(diag.patches.length).toBeGreaterThan(0)
    expect(diag.coverage.some((c) => c.status === 'processing-failed')).toBe(true)
    for (const p of diag.patches) {
      expect(p.data.includes(0x00)).toBe(false)
    }

    const hp = buildIsolatedPacketResult({
      packetIndex: 0,
      capturedLength: data.length,
      linkType: 1,
      data,
      policy: HIGH_PRIVACY_POLICY,
      unit: 'packet',
      reason: 'sanitizer-exception',
      safePrefixEnd: 14,
    })
    expect(hp.drop).toBe(true)
    expect(hp.coverage.some((c) => c.status === 'processing-failed')).toBe(true)
  })

  it('unparseable L2 (linkType without headers) masks entire frame including MAC bytes', () => {
    // LINKTYPE_RAW (101) — linkLayerEnd returns 0 → full-frame mask, never leave raw L2.
    const raw = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    const diag = buildIsolatedPacketResult({
      packetIndex: 0,
      capturedLength: raw.length,
      linkType: 101,
      data: raw,
      policy: DIAGNOSTIC_POLICY,
      unit: 'packet',
      reason: 'sanitizer-exception',
      safePrefixEnd: 0,
    })
    expect(diag.drop).toBe(false)
    expect(diag.patches.length).toBe(1)
    expect(diag.patches[0]!.offset).toBe(0)
    expect(diag.patches[0]!.data.length).toBe(raw.length)
    expect(Buffer.from(diag.patches[0]!.data).equals(Buffer.from(raw))).toBe(false)
    expect(diag.patches[0]!.data.includes(0xaa)).toBe(false)
  })

  it('sanitizeReassembledView never throws to caller (per-flow isolation)', async () => {
    const { sanitizeReassembledView } = await import('../../../src/pcap/reassembly/sipOverReassembled')
    const { createTestSessionMapping } = await import('../../../src/pcap/anonymization/testModeSeed')
    const mapping = createTestSessionMapping('t07-reass-view')
    const view = {
      status: 'complete' as const,
      transport: 'tcp' as const,
      flowKey: 'f',
      bytes: new Uint8Array([0x00, 0xff, 0xfe, 0x01, 0x02]),
      provenance: [],
      contributingPacketIndices: [0],
      srcPort: 5060,
      dstPort: 5060,
    }
    expect(() =>
      sanitizeReassembledView(view as never, mapping, 'tcp'),
    ).not.toThrow()
    expect(sanitizeReassembledView(view as never, mapping, 'tcp').size).toBe(0)
  })

  it('applyReassemblyPatchesToResults isolates a throwing stream from siblings', () => {
    const goodPatch = { offset: 42, data: new Uint8Array([0x11, 0x22]) }
    const results: PacketSanitizationResult[] = [
      { packetIndex: 0, patches: [], drop: false, coverage: [], issues: [] },
      { packetIndex: 1, patches: [], drop: false, coverage: [], issues: [] },
    ]
    const packets = [envelope(new Uint8Array(64), 0), envelope(new Uint8Array(64), 1)]
    const mapping = new SessionMapping(undefined, { seed: 't07-reass' })
    const reassembly = {
      views: [
        {
          status: 'complete',
          transport: 'tcp',
          flowKey: 'bad',
          contributingPacketIndices: [0],
          buffer: new Uint8Array(0),
        },
        {
          status: 'complete',
          transport: 'tcp',
          flowKey: 'good',
          contributingPacketIndices: [1],
          buffer: new Uint8Array(8),
        },
      ],
    } as unknown as ReassemblyContext

    const spy = vi.spyOn(sipOverReassembled, 'sanitizeReassembledView').mockImplementation((view) => {
      if (view.flowKey === 'bad') throw new Error('stream-sanitizer-boom')
      return new Map([[1, [goodPatch]]])
    })
    try {
      applyReassemblyPatchesToResults(results, reassembly, mapping, packets)
      expect(results[0]!.patches).toHaveLength(0)
      expect(results[1]!.patches).toEqual([goodPatch])
    } finally {
      spy.mockRestore()
    }
  })

  it('discoverPacket never throws when sanitize path isolates', () => {
    const data = buildEthIpUdp([10, 1, 2, 3], [8, 8, 8, 8], 40000, 53, latin1('x'))
    const result = discoverPacket(
      {
        index: 0,
        data,
        capturedLength: data.length,
        originalLength: data.length,
        linkType: 1,
      },
      1,
      DIAGNOSTIC_POLICY,
    )
    expect(result.packetIndex).toBe(0)
    expect(result.coverage.every((c) => c.status !== 'covered' || c.protocol !== 'processing-failed')).toBe(true)
  })

  it('plan build records isolation incident and keeps other packets', () => {
    const good = envelope(
      buildEthIpUdp([10, 0, 0, 9], [1, 1, 1, 1], 12345, 53, latin1('ok')),
      0,
    )
    const badData = buildEthIpUdp([10, 0, 0, 8], [1, 1, 1, 1], 12345, 53, latin1('bad'))
    const bad = envelope(badData, 1)
    const packets = [good, bad]
    const profile = createPresetProfile('diagnostic')
    const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 'g', 'iso.pcap')
    // Inject isolation on packet 1 as if sanitizer failed.
    const pd = [...discovery.packetDiscovery]
    const isolated = buildIsolatedPacketResult({
      packetIndex: 1,
      capturedLength: bad.capturedLength,
      linkType: 1,
      data: bad.data,
      policy: DIAGNOSTIC_POLICY,
      unit: 'packet',
      reason: 'sanitizer-exception',
      safePrefixEnd: 14,
      deferPatchResolution: true,
    })
    pd[1] = {
      ...pd[1]!,
      coverage: isolated.coverage,
      issues: isolated.issues,
      drop: isolated.drop,
      isolationFallback: { unit: 'packet', reason: 'sanitizer-exception' },
      resolvePatches: () => isolated.patches,
    }
    const authority = new MappingAuthority({
      ip: profile.mapping.ip,
      mac: profile.mapping.mac,
      timestamps: profile.mapping.timestamps,
      ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
      vlan: profile.mapping.vlan,
    }, { seed: 't07-isolation-seed' })
    const ids = identitiesFromDiscovery({ ...discovery, packetDiscovery: pd })
    const resolved = authority.resolve({ generationId: 'g', sourceId: 'iso.pcap', identities: ids })
    if (!resolved.ok) throw new Error('resolve failed')
    const log = new IncidentLog()
    const plan = buildDeterministicPlan({
      generationId: 'g',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'iso.pcap',
      packets,
      policy: DIAGNOSTIC_POLICY,
      snapshot: resolved.snapshot,
      packetDiscovery: pd,
      classicHeader: {
        format: CaptureFormat.ClassicPcap,
        endian: Endian.Little,
        timestampResolution: TimestampResolution.Microseconds,
        versionMajor: 2,
        versionMinor: 4,
        snapLen: 65535,
        linkType: 1,
        tzOffset: 0,
        sigfigs: 0,
      },
      sourceId: 'iso.pcap',
      incidentLog: log,
    })
    expect(plan.packets).toHaveLength(2)
    expect(plan.incidents?.totalFailures).toBeGreaterThan(0)
    expect(JSON.stringify(plan.incidents)).not.toContain('10.0.0.8')
    const built = buildCaptureFromPlan(plan, packets)
    const out = readClassicPcap(built.buffer).packets
    expect(out).toHaveLength(2)
    // Original payload of isolated packet must not appear.
    const out1 = out[1]!.data
    expect(Buffer.from(out1).includes(Buffer.from('bad'))).toBe(false)
  })
})

describe('T07 line isolation', () => {
  it('detector throw on one line masks that line and continues', () => {
    const session = new DetectionSession({
      onProgress: () => undefined,
      onRuleStarted: () => undefined,
      onHeartbeat: () => undefined,
    })
    session.start('req-line', createDefaultRulesetConfig())

    const spy = vi.spyOn(detectLine, 'detectOnPhysicalLine')
    spy.mockImplementation((text, lineNumber, start) => {
      if (lineNumber === 2) throw new Error('boom')
      return []
    })

    session.pushTextChunk('line-one\nline-two-SECRET\nline-three\n', true)
    const result = session.finalizeDetection()
    spy.mockRestore()

    expect(result.incidents.totalFailures).toBe(1)
    expect(result.incidents.incidents[0]?.unit).toBe('line')
    expect(result.incidents.incidents[0]?.lineNumber).toBe(2)
    expect(JSON.stringify(result.incidents)).not.toContain('SECRET')
    expect(result.entities.some((e) => e.sourceId === LINE_ISOLATION_DETECTOR_ID)).toBe(true)
    const iso = result.entities.find((e) => e.sourceId === LINE_ISOLATION_DETECTOR_ID)
    expect(iso?.replacement).toMatch(/^x+$/)
    expect(iso?.originalSample).toBe('')
  })

  it.each([
    ['LF', 'one\nLINE-TWO-SECRET\nthree\n'],
    ['CRLF', 'one\r\nLINE-TWO-SECRET\r\nthree\n'],
    ['CR', 'one\rLINE-TWO-SECRET\rthree\r'],
  ])('preserves %s endings on isolated line (export transform matches plan)', (label, original) => {
    const session = new DetectionSession({
      onProgress: () => undefined,
      onRuleStarted: () => undefined,
      onHeartbeat: () => undefined,
    })
    session.start(`req-eol-${label}`, createDefaultRulesetConfig())
    const spy = vi.spyOn(detectLine, 'detectOnPhysicalLine')
    spy.mockImplementation((_text, lineNumber) => {
      if (lineNumber === 2) throw new Error('boom')
      return []
    })
    session.pushTextChunk(original, true)
    const result = session.finalizeDetection()
    spy.mockRestore()

    const iso = result.entities.find((e) => e.sourceId === LINE_ISOLATION_DETECTOR_ID)
    expect(iso?.replacement).toMatch(/^x+$/)
    const secret = 'LINE-TWO-SECRET'
    const start = original.indexOf(secret)
    expect(start).toBeGreaterThanOrEqual(0)
    const entities = result.entities.map((e) => ({
      key: e.key,
      category: e.category,
      enabled: true,
      replacement: e.replacement,
      originalSample: '',
      normalized: e.normalized,
      sourceId: e.sourceId,
    }))
    const entityIndexByKey = new Map(entities.map((e, i) => [e.key, i]))
    const packed = packResolvedMatches(
      [
        {
          start,
          end: start + secret.length,
          line: 2,
          entityKey: iso!.key,
          category: 'custom',
          detectorId: LINE_ISOLATION_DETECTOR_ID,
          ruleId: LINE_ISOLATION_DETECTOR_ID,
          priority: 10_000,
          confidence: 1,
          original: '',
          normalized: `${LINE_ISOLATION_DETECTOR_ID}:2`,
        },
      ],
      entityIndexByKey,
      () => true,
    )
    const plan = buildReplacementPlan(packed, entities)
    const exported = transformWithPlan(original, packed, plan)
    expect(exported.includes(secret)).toBe(false)
    expect(countPhysicalLines(exported)).toBe(countPhysicalLines(original))
  })
})
