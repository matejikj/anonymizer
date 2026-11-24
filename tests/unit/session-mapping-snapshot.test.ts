/**
 * Stage 0 — red regression tests for session mapping snapshot contracts.
 *
 * These tests encode the expected session-scoped published snapshot behaviour.
 * On the current implementation they FAIL because `commitStaging()` /
 * `applyResolveBatch()` publishes only the last batch's identities, not the
 * full MappingRegistry union.
 *
 * Do not "fix" the production bug here — Stage 1 turns these green.
 */

import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import {
  MAPPING_SNAPSHOT_CONSUMERS,
  type CanonicalIdentity,
  type MappingPlanSnapshot,
  type MappingSessionSnapshot,
} from '../../src/mapping/types'
import { MappingWorkerClient } from '../../src/mapping/mappingWorkerClient'
import {
  setSharedMappingClientForTests,
  resetSharedMappingClient,
  getSharedMappingClient,
} from '../../src/mapping/sharedMappingClient'
import { createInProcessMappingWorkerFactory } from '../helpers/inProcessMappingWorker'
import { createInProcessPcapProcessingClient } from '../helpers/inProcessPcapProcessingWorker'
import { FakeDetectionWorker } from '../helpers/fakeDetectionWorker'
import { DetectionWorkerClient } from '../../src/app/workerClient'
import {
  clearCorrelationSession,
  createPcapSourceAdapter,
  createTextSourceAdapter,
  getCorrelationSource,
  listCorrelationSources,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  resetCorrelationUiPhase,
  runCorrelationSession,
  stageCorrelationDescriptors,
} from '../../src/correlation'
import { buildBundlePayloadFromSnapshot } from '../../src/mapping/bundle/buildPayload'
import {
  buildShareableCorrelationGroups,
  assertShareableManifestHasNoLeaks,
} from '../../src/correlation/export/correlationShareManifest'
import { CaptureFormat, Endian, TimestampResolution } from '../../src/pcap/domain/types'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import type { PacketEnvelope } from '../../src/pcap/domain/types'
import type { StagedSourceDescriptor } from '../../src/correlation/types'
import { useAppStore } from '../../src/app/store'

const IP_A = '10.0.0.1'
const IP_B = '10.0.0.2'
const IP_C = '10.66.77.88'

function ipIdentity(canonical: string): CanonicalIdentity {
  return {
    category: 'ip',
    canonical,
    constraint: { kind: 'ipv4-wire' },
    originalSpelling: canonical,
    source: { detectorId: 'stage0-test' },
  }
}

function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

function ethIpv4Packet(
  srcIp: [number, number, number, number],
  dstIp: [number, number, number, number] = [192, 168, 1, 1],
): Uint8Array {
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
  const data = ethIpv4Packet(srcIp)
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

function canonicalsOf(snapshot: MappingSessionSnapshot | MappingPlanSnapshot | null): string[] {
  return (snapshot?.entries ?? []).map((e) => e.canonical).sort()
}

function registerTextPcapAdapters(): void {
  const det = () => new DetectionWorkerClient({}, () => new FakeDetectionWorker())
  registerSourceAdapter(createTextSourceAdapter({ createDetectionClient: det }))
  registerSourceAdapter(createPcapSourceAdapter({
    createProcessingClient: createInProcessPcapProcessingClient,
  }))
}

async function expectSessionOk(
  descriptors: readonly StagedSourceDescriptor[],
): Promise<void> {
  await stageCorrelationDescriptors(descriptors)
  const result = await runCorrelationSession()
  if (!('ok' in result) || !result.ok) {
    const detail = 'code' in result ? `${result.code}: ${result.message}` : JSON.stringify(result)
    throw new Error(`correlation session failed (setup, not mapping contract): ${detail}`)
  }
}

describe('Stage 0 — mapping snapshot contracts', () => {
  it('documents request vs session consumer scopes (two-type decision)', () => {
    expect(MAPPING_SNAPSHOT_CONSUMERS.buildPlan).toBe('request')
    expect(MAPPING_SNAPSHOT_CONSUMERS.sourcePlan).toBe('request')
    expect(MAPPING_SNAPSHOT_CONSUMERS.publishedSnapshot).toBe('session')
    expect(MAPPING_SNAPSHOT_CONSUMERS.mappingBundle).toBe('session')
    expect(MAPPING_SNAPSHOT_CONSUMERS.shareableManifest).toBe('session')
    expect(MAPPING_SNAPSHOT_CONSUMERS.correlationReview).toBe('session')
  })
})

describe('Stage 0 — MappingAuthority session snapshot union (RED)', () => {
  it('after two commits with disjoint IPs, published snapshot contains both', () => {
    const authority = new MappingAuthority()

    const staged1 = authority.resolveStaging({
      generationId: 'g-s0',
      sourceId: 'src-a',
      identities: [ipIdentity(IP_A)],
    })
    expect(staged1.ok).toBe(true)
    if (!staged1.ok) return
    expect(canonicalsOf(staged1.snapshot as MappingPlanSnapshot)).toEqual([IP_A])

    const commit1 = authority.commitStaging()
    expect(commit1.ok).toBe(true)

    const staged2 = authority.resolveStaging({
      generationId: 'g-s0',
      sourceId: 'src-b',
      identities: [ipIdentity(IP_B)],
    })
    expect(staged2.ok).toBe(true)
    if (!staged2.ok) return
    expect(canonicalsOf(staged2.snapshot as MappingPlanSnapshot)).toEqual([IP_B])

    const commit2 = authority.commitStaging()
    expect(commit2.ok).toBe(true)
    if (!commit2.ok) return

    // Registry already holds the full session — distinguishes mapping-contract bug from resolve failure.
    const registryCanonicals = authority
      .getRegistry()
      .entries()
      .map((e) => e.canonical)
      .sort()
    expect(registryCanonicals).toEqual([IP_A, IP_B].sort())

    const session = authority.getPublishedSnapshot() as MappingSessionSnapshot | null
    expect(canonicalsOf(session)).toEqual([IP_A, IP_B].sort())
    expect(canonicalsOf(commit2.snapshot as MappingSessionSnapshot)).toEqual([IP_A, IP_B].sort())
  })
})

describe('Stage 0 — correlation session published snapshot (RED)', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationUiPhase()
    resetCorrelationAdaptersForTests()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    registerTextPcapAdapters()
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationAdaptersForTests()
    resetCorrelationUiPhase()
  })

  it('two text sources with disjoint IPs keep both identities in published snapshot', async () => {
    await expectSessionOk([
      { sourceId: 'a', kind: SK.Text, file: textFile('a.log', `host ${IP_A} seen\n`) },
      { sourceId: 'b', kind: SK.Text, file: textFile('b.log', `peer ${IP_B} seen\n`) },
    ])

    // Discovery succeeded per source (not a detector failure).
    expect(getCorrelationSource('a')?.discovery?.identities.some((i) => i.canonical === IP_A)).toBe(true)
    expect(getCorrelationSource('b')?.discovery?.identities.some((i) => i.canonical === IP_B)).toBe(true)

    const snap = getSharedMappingClient().getPublishedSnapshot()
    expect(canonicalsOf(snap)).toEqual(expect.arrayContaining([IP_A, IP_B]))
    expect(new Set(canonicalsOf(snap))).toEqual(new Set([IP_A, IP_B]))
  })

  it('text then pcap keeps both source identities in session snapshot', async () => {
    await expectSessionOk([
      { sourceId: 't', kind: SK.Text, file: textFile('t.log', `peer ${IP_B}\n`) },
      { sourceId: 'p', kind: SK.Pcap, file: pcapFile('c.pcap', [10, 66, 77, 88]) },
    ])

    const canons = canonicalsOf(getSharedMappingClient().getPublishedSnapshot())
    expect(canons).toEqual(expect.arrayContaining([IP_B, IP_C]))
  })
})

describe('Stage 0 — correlation mapping bundle union (RED)', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationUiPhase()
    resetCorrelationAdaptersForTests()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    registerTextPcapAdapters()
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationAdaptersForTests()
    resetCorrelationUiPhase()
  })

  it('bundle payload contains unique identities from every source, not only last commit', async () => {
    await expectSessionOk([
      { sourceId: 'a', kind: SK.Text, file: textFile('a.log', `host ${IP_A}\n`) },
      { sourceId: 'b', kind: SK.Text, file: textFile('b.log', `host ${IP_B}\n`) },
      { sourceId: 'p', kind: SK.Pcap, file: pcapFile('c.pcap', [10, 66, 77, 88]) },
    ])

    const snap = getSharedMappingClient().getPublishedSnapshot()
    expect(snap).not.toBeNull()
    if (!snap) return

    const bundleSources = listCorrelationSources()
      .filter((s) => s.phase === 'planned')
      .map((s) => ({
        id: s.sourceId,
        kind: (s.kind === SK.Pcap ? 'pcap' : 'text') as 'text' | 'pcap',
        name: s.fileName,
      }))

    const payload = buildBundlePayloadFromSnapshot(snap, bundleSources)
    const payloadCanonicals = payload.entries.map((e) => e.canonical)

    expect(payloadCanonicals).toEqual(expect.arrayContaining([IP_A, IP_B, IP_C]))
  })
})

describe('Stage 0 — shareable manifest multi-representation union (RED)', () => {
  beforeEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationUiPhase()
    resetCorrelationAdaptersForTests()
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    registerTextPcapAdapters()
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
    resetCorrelationAdaptersForTests()
    resetCorrelationUiPhase()
  })

  it('keeps shared and later identities in session snapshot for shareable export', async () => {
    await expectSessionOk([
      { sourceId: 'shared-text', kind: SK.Text, file: textFile('shared.log', `host ${IP_C}\n`) },
      { sourceId: 'shared-pcap', kind: SK.Pcap, file: pcapFile('shared.pcap', [10, 66, 77, 88]) },
      { sourceId: 'later', kind: SK.Text, file: textFile('later.log', `other ${IP_B}\n`) },
    ])

    const snap = getSharedMappingClient().getPublishedSnapshot()
    expect(snap).not.toBeNull()
    if (!snap) return
    expect(snap.scope).toBe('session')
    expect(canonicalsOf(snap)).toEqual(expect.arrayContaining([IP_C, IP_B]))

    // text+pcap both use ipv4-wire → one shared alias under linking; multi-rep groups
    // are covered by mapping-session-authority tests with text-ascii + ipv4-wire.
    const json = JSON.stringify({
      format: 'rnd-log-anonymizer-correlation-manifest',
      schemaVersion: 1,
      partial: false,
      sources: [
        { sourceId: 'a', outputFileName: 'a.anonym.log', kind: 'text' },
        { sourceId: 'b', outputFileName: 'b.anonym.pcap', kind: 'pcap' },
      ],
      correlationGroups: buildShareableCorrelationGroups(snap),
    })
    assertShareableManifestHasNoLeaks(json, [IP_C, IP_B, '10.66.77.88'])
  })
})
