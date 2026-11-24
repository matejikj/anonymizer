import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import {
  setSharedMappingClientForTests,
  resetSharedMappingClient,
  getSharedMappingClient,
} from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import {
  createInProcessPcapProcessingClient,
  type InProcessPcapProcessingStats,
} from '../helpers/inProcessPcapProcessingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import {
  addCorrelationSource,
  clearCorrelationSession,
  createPcapSourceAdapter,
  createTextSourceAdapter,
  enterCorrelationFailedPhase,
  getCorrelationSource,
  getCorrelationUiPhase,
  listCorrelationSources,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  resetCorrelationUiPhase,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import {
  buildShareableCorrelationManifest,
  assertShareableManifestHasNoLeaks,
} from '../../src/correlation/export/correlationShareManifest'
import { CaptureFormat, Endian, TimestampResolution } from '../../src/pcap/domain/types'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import type { PacketEnvelope } from '../../src/pcap/domain/types'
import { useAppStore } from '../../src/app/store'
import type { SourceAdapter } from '../../src/correlation/types'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

function ethIpv4Packet(srcIp: [number, number, number, number], dstIp: [number, number, number, number]): Uint8Array {
  const pkt = new Uint8Array(14 + 20 + 20)
  pkt.set([0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0)
  pkt.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  pkt[12] = 0x08
  pkt[13] = 0x00
  pkt[14] = 0x45
  pkt[16] = 0x00
  pkt[17] = 40
  pkt[14 + 8] = 64
  pkt[14 + 9] = 6
  pkt.set(srcIp, 14 + 12)
  pkt.set(dstIp, 14 + 16)
  const tcpOff = 34
  pkt[tcpOff] = 0x1f
  pkt[tcpOff + 1] = 0x90
  pkt[tcpOff + 2] = 0x00
  pkt[tcpOff + 3] = 0x50
  pkt[tcpOff + 12] = 0x50
  return pkt
}

function pcapFile(name: string, srcIp: [number, number, number, number]): File {
  const data = ethIpv4Packet(srcIp, [192, 168, 1, 1])
  const packets: PacketEnvelope[] = [
    {
      packetNumber: 0,
      timestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
      capturedLength: data.length,
      originalLength: data.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 0,
      data,
    },
  ]
  const buf = writeClassicPcap({
    header: {
      format: CaptureFormat.ClassicPcap,
      endian: Endian.Little,
      timestampResolution: TimestampResolution.Micro,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    },
    packets,
  })
  return new File([buf], name, { type: 'application/octet-stream' })
}

describe('Stage 31 multi-source integration gate', () => {
  let pcapProcessingStats: InProcessPcapProcessingStats

  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationUiPhase()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    pcapProcessingStats = { processRequests: 0, buildPlanRequests: 0, terminations: 0 }
    registerSourceAdapter(createPcapSourceAdapter({
      createProcessingClient: () => createInProcessPcapProcessingClient(pcapProcessingStats),
    }))
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationUiPhase()
  })

  it('DOT + AS share one IP alias across sources', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'dot', kind: SK.Text, file: textFile('dot.log', 'peer 10.0.0.5 ok\n') },
      { sourceId: 'as', kind: SK.Text, file: textFile('as.log', 'server 10.0.0.5 up\n') },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)

    const snap = getSharedMappingClient().getPublishedSnapshot()
    const ipEntries = snap!.entries.filter((e) => e.canonical === '10.0.0.5')
    expect(ipEntries.length).toBeGreaterThanOrEqual(1)
    const alias = ipEntries[0]!.alias
    expect(ipEntries.every((e) => e.alias === alias || e.aliases.some((a) => a.alias === alias))).toBe(true)

    const fromDiscovery =
      Boolean(getCorrelationSource('dot')?.discovery?.identities.some((i) => i.canonical === '10.0.0.5')) &&
      Boolean(getCorrelationSource('as')?.discovery?.identities.some((i) => i.canonical === '10.0.0.5'))
    expect(fromDiscovery).toBe(true)
  })

  it('unique value of one source does not appear in the other source occurrence index', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'a', kind: SK.Text, file: textFile('a.log', 'only-a 10.0.0.1\n') },
      { sourceId: 'b', kind: SK.Text, file: textFile('b.log', 'only-b 10.0.0.2\n') },
    ])
    await runCorrelationSession()

    const aIds = new Set(
      (getCorrelationSource('a')?.discovery?.identities ?? []).map((i) => i.canonical),
    )
    const bIds = new Set(
      (getCorrelationSource('b')?.discovery?.identities ?? []).map((i) => i.canonical),
    )
    expect(aIds.has('10.0.0.1')).toBe(true)
    expect(bIds.has('10.0.0.1')).toBe(false)
    expect(bIds.has('10.0.0.2')).toBe(true)
    expect(aIds.has('10.0.0.2')).toBe(false)

    const aOcc = (getCorrelationSource('a')?.discovery?.identities ?? []).flatMap((i) =>
      i.occurrence ? [i.occurrence] : [],
    )
    const bOcc = (getCorrelationSource('b')?.discovery?.identities ?? []).flatMap((i) =>
      i.occurrence ? [i.occurrence] : [],
    )
    expect(aOcc.every((o) => o.sourceId === 'a')).toBe(true)
    expect(bOcc.every((o) => o.sourceId === 'b')).toBe(true)
  })

  it('two PCAPs share wire-valid IP/MAC aliases', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'p1', kind: SK.Pcap, file: pcapFile('one.pcap', [10, 0, 0, 55]) },
      { sourceId: 'p2', kind: SK.Pcap, file: pcapFile('two.pcap', [10, 0, 0, 55]) },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)

    const snap = getSharedMappingClient().getPublishedSnapshot()
    const ip = snap!.entries.find((e) => e.canonical === '10.0.0.55')
    expect(ip?.alias).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
    const mac = snap!.entries.find((e) => e.category === 'mac')
    expect(mac?.alias).toBeTruthy()

    expect(pcapProcessingStats).toEqual({
      processRequests: 2,
      buildPlanRequests: 2,
      terminations: 2,
    })
    for (const sourceId of ['p1', 'p2']) {
      const discovery = getCorrelationSource(sourceId)?.discovery
      expect(discovery?.kind).toBe('pcap')
      if (discovery?.kind !== 'pcap') continue
      expect('session' in discovery).toBe(false)
      expect('packets' in discovery.container).toBe(false)
      expect(discovery.container.descriptors).toHaveLength(1)
    }
  })

  it('text + PCAP share wire-valid IPv4 alias', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'log', kind: SK.Text, file: textFile('net.log', 'peer 10.0.0.55 connected\n') },
      { sourceId: 'cap', kind: SK.Pcap, file: pcapFile('net.pcap', [10, 0, 0, 55]) },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)

    const snap = getSharedMappingClient().getPublishedSnapshot()
    const related = snap!.entries.filter((e) => e.canonical === '10.0.0.55')
    expect(related.length).toBeGreaterThanOrEqual(1)
    const alias = related[0]!.alias
    expect(alias).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
    expect(related.every((e) => e.alias === alias || e.aliases.some((a) => a.alias === alias))).toBe(true)
  })

  it('shareable correlation manifest must-not-leak originals', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'dot', kind: SK.Text, file: textFile('dot.log', 'peer 10.0.0.5 ok\n') },
      { sourceId: 'as', kind: SK.Text, file: textFile('as.log', 'server 10.0.0.5 up\n') },
    ])
    await runCorrelationSession()
    const snap = getSharedMappingClient().getPublishedSnapshot()!
    const sources = listCorrelationSources()
    const manifest = buildShareableCorrelationManifest({
      sources,
      snapshot: snap,
      partial: false,
    })
    expect(manifest).toBeTruthy()
    const json = JSON.stringify(manifest)
    assertShareableManifestHasNoLeaks(json, ['10.0.0.5'])
    expect(json).not.toContain('10.0.0.5')
  })

  it('parser failure enters failed phase and keeps AppPhase on processing for recovery UI', async () => {
    resetCorrelationAdaptersForTests()
    const boom: SourceAdapter = {
      kind: SK.Text,
      probe: () => ({ ok: true, kind: SK.Text }),
      preflight: async (file) => ({ ok: true, byteLength: file.size, kind: SK.Text }),
      discover: async ({ sourceId }) => {
        if (sourceId === 'bad') throw new Error('parser boom')
        return {
          kind: 'text',
          identities: [],
          detection: {
            generationId: 'g',
            text: '',
            lineEndings: new Uint8Array(),
            matches: { starts: new Uint32Array(), ends: new Uint32Array(), types: new Uint8Array(), ruleIds: [] },
            stats: { lineCount: 0, entityCounts: {}, durationMs: 0 },
          },
          text: '',
          lineEndings: new Uint8Array(),
        } as never
      },
      buildPlan: async () =>
        ({
          kind: 'text',
          replacementPlan: { replacements: [] },
          exportBlocked: false,
        }) as never,
    }
    registerSourceAdapter(boom)

    await stageCorrelationDescriptors([
      { sourceId: 'good', kind: SK.Text, file: textFile('good.log', '10.0.0.9\n') },
      { sourceId: 'bad', kind: SK.Text, file: textFile('bad.log', 'x\n') },
    ])

    const result = await runCorrelationSession()
    expect('ok' in result && result.ok).toBe(false)
    enterCorrelationFailedPhase('staging')
    expect(getCorrelationUiPhase().kind).toBe('failed')
    expect(useAppStore.getState().phase).toBe('correlation-processing')
    expect(getCorrelationSource('bad')?.phase).toBe('failed')
  })

  it('cancel add-source leaves existing plans and mappingRevision intact', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'base', kind: SK.Text, file: textFile('base.log', '10.0.0.3\n') },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)
    if (!('ok' in processed) || !processed.ok) return

    const revisionBefore = processed.mappingRevision
    const planBefore = JSON.stringify(getCorrelationSource('base')?.plan)
    const ac = new AbortController()
    ac.abort()

    const added = await addCorrelationSource(
      { sourceId: 'extra', kind: SK.Text, file: textFile('extra.log', '10.0.0.3 and 10.0.0.9\n') },
      { signal: ac.signal },
    )
    expect('ok' in added && added.ok).toBe(false)
    expect(getCorrelationSource('extra')).toBeNull()
    expect(JSON.stringify(getCorrelationSource('base')?.plan)).toBe(planBefore)
    expect(getSharedMappingClient().getPublishedRevision()).toBe(revisionBefore)
  })
})
