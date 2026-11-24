/**
 * T-01 kernel conformance — catalog, pull reader, frozen plans, onboarding example.
 */
import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { openPullCaptureReader } from '../../../src/pcap/capture/pullCaptureReader'
import { processCapture } from '../../../src/pcap/processing/processingPipeline'
import { policyFromPreset } from '../../../src/pcap/sanitize/engine'
import { PCAP_KERNEL_BUDGETS } from '../../../src/domain/capabilityContract'
import {
  getSharedProtocolManifest,
  resetSharedProtocolManifestForTests,
  catalogLegacyModules,
  echoUdpExampleModule,
  buildEchoUdpDatagram,
  ECHO_UDP_EXAMPLE_PORT,
  createFactWriter,
  SemanticJournalBuilder,
  renderSymbolicOperations,
  APPLICATION_HANDLER_ORDER,
  KERNEL_ENGINE_VERSION,
  type SymbolicOperation,
} from '../../../src/pcap/kernel'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { generateClassicPcap } from '../fixtures/generate'

describe('T-01.0 baseline inventory anchors', () => {
  it('publishes kernel budgets and engine version', () => {
    expect(PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes).toBe(64 * 1024 * 1024)
    expect(PCAP_KERNEL_BUDGETS.reassemblyMaxBytes).toBe(32 * 1024 * 1024)
    expect(PCAP_KERNEL_BUDGETS.progressMaxIntervalMs).toBe(250)
    expect(KERNEL_ENGINE_VERSION).toMatch(/^t01-/)
  })

  it('records synthetic fixture content hash for micro classic PCAP', () => {
    const buf = generateClassicPcap(4, 64)
    const hash = createHash('sha256').update(buf).digest('hex')
    expect(hash).toHaveLength(64)
    expect(hash).toBe(createHash('sha256').update(generateClassicPcap(4, 64)).digest('hex'))
  })
})

describe('T-01.1 manifest / catalog', () => {
  it('analysis.ts derives modules only from kernel catalog (T-01.A)', async () => {
    const { readFile } = await import('node:fs/promises')
    const analysisSrc = await readFile(
      new URL('../../../src/pcap/protocols/analysis.ts', import.meta.url),
      'utf8',
    )
    expect(analysisSrc).not.toMatch(/\bALL_MODULES\b/)
    expect(analysisSrc).toMatch(/catalogLegacyModules/)
  })

  it('exposes a single compiled manifest without ALL_MODULES fork', () => {
    resetSharedProtocolManifestForTests()
    const manifest = getSharedProtocolManifest()
    const compiled = manifest.compile()
    expect(compiled.all.length).toBeGreaterThanOrEqual(16)
    expect(compiled.byId.has('ethernet')).toBe(true)
    expect(compiled.byId.has('echo-udp-example')).toBe(true)
    expect(catalogLegacyModules().map((m) => m.id)).toContain('ipv4')
    expect(APPLICATION_HANDLER_ORDER.map((h) => h.id)).toContain('sip')
  })
})

describe('T-01.2 pull reader + session without packets', () => {
  it('pulls leased batches and releases them', async () => {
    const ab = generateClassicPcap(20, 128)
    const blob = new Blob([ab])
    const reader = await openPullCaptureReader(blob, CaptureFormat.ClassicPcap, {
      batchMaxRecords: 8,
      batchMaxBytes: 256 * 1024,
    })
    expect(reader.descriptors.length).toBe(20)
    let batches = 0
    let peak = 0
    for (;;) {
      const batch = await reader.pull()
      if (!batch) break
      batches++
      peak = Math.max(peak, reader.leaseArena.stats.liveBytes)
      batch.release()
      expect(reader.leaseArena.stats.liveLeases).toBe(0)
    }
    expect(batches).toBeGreaterThan(1)
    expect(peak).toBeGreaterThan(0)
    expect(reader.leaseArena.stats.liveBytes).toBe(0)
  })

  it('AbortSignal throws cancelled from pull read loop (T-01.G)', async () => {
    const ab = generateClassicPcap(48, 512)
    const ac = new AbortController()
    const reader = await openPullCaptureReader(new Blob([ab]), CaptureFormat.ClassicPcap, {
      batchMaxRecords: 4,
      batchMaxBytes: 2048,
      signal: ac.signal,
    })
    const first = await reader.pull()
    expect(first).not.toBeNull()
    first!.release()
    ac.abort()
    expect(reader.cancelled).toBe(true)
    await expect(reader.pull()).rejects.toThrow('cancelled')
  })

  it('processCapture retains descriptors, not packets', async () => {
    const ab = generateClassicPcap(6, 96)
    const session = await processCapture({
      blob: new Blob([ab]),
      fileName: 't01.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('diagnostic'),
      generationId: 'g-t01',
      sourceId: 's-t01',
    })
    expect(session.descriptors.length).toBe(6)
    expect(session.sourceBlob).toBeInstanceOf(Blob)
    expect(session.packets).toBeUndefined()
    expect(session.journal.packets.length).toBe(6)
    expect(session.journal.generationId).toBe('g-t01')
    expect(session.discovery.packetDiscovery.every((p) => p.frozenPlan !== undefined)).toBe(true)
    expect(session.budgetSnapshot).toBeDefined()
    expect(session.leaseStats.totalReleased).toBeGreaterThan(0)
  })
})

describe('T-01.6 onboarding echo-udp example', () => {
  it('production sanitizePacket dispatches via kernel bridge (V12)', async () => {
    const { sanitizePacket, DIAGNOSTIC_POLICY } = await import('../../../src/pcap/sanitize')
    const { buildEthIpUdp } = await import('../fixtures/voipCorpus')
    const { SessionMapping } = await import('../../../src/pcap/anonymization/mapping')
    const payload = buildEchoUdpDatagram(0xabcdef, new TextEncoder().encode('ECHO_SECRET'))
    const frame = buildEthIpUdp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      ECHO_UDP_EXAMPLE_PORT,
      ECHO_UDP_EXAMPLE_PORT,
      payload,
    )
    const mapping = new SessionMapping(undefined, { seed: 't01-echo-e2e' })
    const r = sanitizePacket(
      {
        index: 0,
        data: frame,
        capturedLength: frame.length,
        originalLength: frame.length,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    expect(r.coverage.some((c) => c.protocol === 'echo-udp-example' && c.status === 'covered')).toBe(
      true,
    )
    expect(r.coverage.some((c) => c.protocol === 'payload' && c.status === 'unsupported')).toBe(
      false,
    )
    const out = frame.slice()
    for (const p of r.patches) out.set(p.data, p.offset)
    expect(new TextDecoder('latin1').decode(out).includes('ECHO_SECRET')).toBe(false)
    expect(Array.from(out.subarray(14 + 20 + 8 + 4, 14 + 20 + 8 + 7))).not.toEqual([
      0xab, 0xcd, 0xef,
    ])
  })

  it('analyze emits map + mask ops without central sanitize switch', () => {
    const payload = buildEchoUdpDatagram(0x123456, new Uint8Array([1, 2, 3, 4]))
    const journal = new SemanticJournalBuilder('g', 's')
    const ops: SymbolicOperation[] = []
    const out = createFactWriter(journal, ops)
    const probe = echoUdpExampleModule.probe(
      { bytes: payload, byteOffset: 0, byteLength: payload.length, leaseId: 1 },
      {
        packetIndex: 0,
        linkType: 1,
        nestingDepth: 0,
        transport: 'udp',
        srcPort: ECHO_UDP_EXAMPLE_PORT,
        dstPort: ECHO_UDP_EXAMPLE_PORT,
      },
    )
    expect(probe.decision).toBe('claim')
    echoUdpExampleModule.analyze(
      { bytes: payload, byteOffset: 0, byteLength: payload.length, leaseId: 1 },
      {
        generationId: 'g',
        sourceId: 's',
        packetIndex: 0,
        linkType: 1,
        nestingDepth: 0,
        logicalMessageId: 0,
        transport: 'udp',
        srcPort: ECHO_UDP_EXAMPLE_PORT,
        dstPort: ECHO_UDP_EXAMPLE_PORT,
      },
      out,
    )
    expect(ops.some((o) => o.kind === 'map' && o.category === 'radioId')).toBe(true)
    expect(ops.some((o) => o.kind === 'mask' && o.length === 4)).toBe(true)

    const mapping = new SessionMapping(undefined, { seed: 't01-echo' })
    mapping.map('radioId', '1193046')
    const patches = renderSymbolicOperations(ops, {
      mapping,
      fingerprints: new FingerprintSession('t01-echo'),
    })
    expect(patches.length).toBeGreaterThanOrEqual(1)
    const idPatch = patches.find((p) => p.offset === 4)
    expect(idPatch?.data.length).toBe(3)
    expect(Array.from(idPatch!.data)).not.toEqual([0x12, 0x34, 0x56])
  })
})

describe('T-01 privacy / docs invariants', () => {
  it('does not put original identity into journal impact entries', () => {
    const journal = new SemanticJournalBuilder('g', 's')
    journal.addImpact({
      protocolId: 'echo-udp-example',
      packetIndex: 0,
      byteCount: 4,
      reason: 'content-redacted',
      disposition: 'mask',
    })
    const frozen = journal.freeze()
    const json = JSON.stringify(frozen.impacts)
    expect(json).not.toMatch(/1193046/)
    expect(json).toContain('content-redacted')
  })

  it('classic writer round-trip still builds a valid blob for pull reader', async () => {
    const packets = [
      {
        packetNumber: 0,
        timestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
        capturedLength: 64,
        originalLength: 64,
        linkType: 1,
        interfaceId: 0,
        sectionIndex: 0,
        fileOffset: 0,
        data: new Uint8Array(64),
      },
    ]
    const ab = writeClassicPcap({
      packets,
      header: {
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
    })
    const reader = await openPullCaptureReader(new Blob([ab]), CaptureFormat.ClassicPcap)
    const batch = await reader.pull()
    expect(batch?.records.length).toBe(1)
    batch?.release()
  })
})
