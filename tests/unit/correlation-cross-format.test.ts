import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import { setSharedMappingClientForTests, resetSharedMappingClient, getSharedMappingClient } from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { createInProcessPcapProcessingClient } from '../helpers/inProcessPcapProcessingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import { canonicalizeIdentity } from '../../src/mapping/canonicalize'
import { CaptureFormat, Endian, TimestampResolution } from '../../src/pcap/domain/types'
import type { PacketEnvelope } from '../../src/pcap/domain/types'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import { buildEthIpUdp } from '../pcap/fixtures/voipCorpus'
import {
  addCorrelationSource,
  clearCorrelationSession,
  createPcapSourceAdapter,
  createTextSourceAdapter,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  resetCorrelationUiPhase,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import { useAppStore } from '../../src/app/store'

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

/** Synthetic E.164 — same digit pattern as other T45 unit fixtures, not a real subscriber. */
const T45_E164 = '+420777123456'

function sipTelPcapFile(name: string, e164: string): File {
  const sipBody = [
    'INVITE sip:trunk@10.0.0.2 SIP/2.0',
    'Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-t45-cf',
    `P-Asserted-Identity: <tel:${e164}>`,
    'From: <sip:anon@10.0.0.1>;tag=t45-cf',
    'To: <sip:b@10.0.0.2>',
    'Call-ID: t45-cf-phone@host',
    'CSeq: 1 INVITE',
    'Content-Length: 0',
    '',
    '',
  ].join('\r\n')
  const data = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, new TextEncoder().encode(sipBody))
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

describe('Stage 25 correlation cross-format integration', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationUiPhase()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    resetCorrelationAdaptersForTests()
    useAppStore.getState().resetSession()
    registerSourceAdapter(
      createTextSourceAdapter({
        createDetectionClient: () => new DetectionWorkerClient({}, () => new FakeDetectionWorker()),
      }),
    )
    registerSourceAdapter(createPcapSourceAdapter({
      createProcessingClient: createInProcessPcapProcessingClient,
    }))
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationUiPhase()
  })

  it('reuses wire-valid alias when second text log shares the same IP identity', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'log-a', kind: SK.Text, file: textFile('a.log', 'peer 10.0.0.77 connected\n') },
    ])
    await runCorrelationSession()

    const snapBefore = getSharedMappingClient().getPublishedSnapshot()
    const aliasBefore = snapBefore?.entries.find((e) => e.canonical === '10.0.0.77')?.alias

    await addCorrelationSource({
      sourceId: 'log-b',
      kind: SK.Text,
      file: textFile('b.log', 'server 10.0.0.77 ok\n'),
    })

    const snapAfter = getSharedMappingClient().getPublishedSnapshot()
    const aliasAfter = snapAfter?.entries.find((e) => e.canonical === '10.0.0.77')?.alias
    expect(aliasBefore).toBeTruthy()
    expect(aliasAfter).toBe(aliasBefore)
    expect(aliasAfter).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
  })

  it('T45 — text tel: and PCAP SIP P-Asserted-Identity share one MappingAuthority phone alias', async () => {
    const canon = canonicalizeIdentity('sip-phone', T45_E164)!
    expect(canon).toBeTruthy()

    await stageCorrelationDescriptors([
      {
        sourceId: 'app-log',
        kind: SK.Text,
        file: textFile('app.log', `established call tel:${T45_E164}\n`),
      },
      {
        sourceId: 'sip-cap',
        kind: SK.Pcap,
        file: sipTelPcapFile('sip.pcap', T45_E164),
      },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)

    const snap = getSharedMappingClient().getPublishedSnapshot()!
    const phoneEntries = snap.entries.filter(
      (e) => e.category === 'sip-phone' && e.canonical === canon,
    )
    expect(phoneEntries).toHaveLength(1)
    expect(phoneEntries[0]!.occurrenceCount).toBeGreaterThanOrEqual(2)
    expect(phoneEntries[0]!.alias).not.toContain('777')
    expect(phoneEntries[0]!.alias).not.toBe(canon)
  })
})
