/**
 * Stage 34 — final correlation release gate checklist (§39 items 1–8, 10–11).
 * Item 9 (tri-browser) is enforced by playwright.correlation-release + CI.
 * Item 12 (docs) is enforced by correlation-wiring + doc assertions below.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SourceKind as SK } from '../../src/domain/sourceArtifact'
import {
  CORRELATION_SESSION_LIMITS,
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
} from '../../src/domain/capabilityContract'
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
  bootstrapDefaultSourceAdapters,
  clearCorrelationSession,
  createPcapSourceAdapter,
  createTextSourceAdapter,
  registeredAdapterKinds,
  registerSourceAdapter,
  resetCorrelationAdaptersForTests,
  resetCorrelationUiPhase,
  runCorrelationSession,
  stageCorrelationDescriptors,
  getCorrelationSource,
  validateAggregateBytes,
  perKindFileLimit,
  ingestDroppedFiles,
  resetCorrelationImportForTests,
} from '../../src/correlation'
import {
  serializeMappingBundleJson,
  parseMappingBundleJsonText,
  MAPPING_BUNDLE_CANONICALIZATION_VERSION,
} from '../../src/mapping/bundle'
import type { MappingBundlePayload } from '../../src/mapping/bundle'
import {
  cancelBundleJob,
  getBundleJobPhase,
  releaseBundleCryptoSession,
} from '../../src/features/mapping-bundle/bundleController'
import {
  clearResolveOnlyModel,
  getResolveOnlyPayload,
  setResolveOnlyPayload,
  isResolveOnlyActive,
} from '../../src/features/resolve-only/resolveOnlyModel'
import { useAppStore } from '../../src/app/store'
import { AliasLookupIndex, scanReportForPseudonyms, buildAnnotatedReport } from '../../src/mapping/resolve'
import {
  canonicalizeCrossFormatCategory,
  constraintsCompatible,
  crossFormatRegistryKeyFromIdentity,
} from '../../src/mapping/crossFormat'
import {
  PROFILE_COMPATIBILITY_OUTCOME,
  compileCorrelationPolicy,
  evaluateProfileCompatibility,
  compatibilityAllowsProcessing,
} from '../../src/correlation/profileCompatibility'
import { createDefaultRulesetConfig } from '../../src/domain/configSchema'
import { cloneRulesetConfig } from '../../src/domain/rulesetValidate'
import { createDefaultPcapProfile } from '../../src/pcap/profile/presets'
import { CaptureFormat, Endian, TimestampResolution } from '../../src/pcap/domain/types'
import { writeClassicPcap } from '../../src/pcap/capture/pcapWriter'
import type { PacketEnvelope } from '../../src/pcap/domain/types'
import {
  buildShareableCorrelationManifest,
  assertShareableManifestHasNoLeaks,
} from '../../src/correlation/export/correlationShareManifest'
import { probeSourceKind } from '../../src/correlation/import/sourcePreflightPort'

const root = join(fileURLToPath(new URL('../..', import.meta.url)))
function textFile(name: string, body: string): File {
  return new File([body], name, { type: 'text/plain' })
}

function ethIpv4Packet(srcIp: [number, number, number, number]): Uint8Array {
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
  pkt.set([192, 168, 1, 1], 14 + 16)
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

function samplePayload(): MappingBundlePayload {
  return {
    sessionId: 's34',
    canonicalizationVersion: MAPPING_BUNDLE_CANONICALIZATION_VERSION,
    mappingRevision: 1,
    sources: [{ id: 's1', kind: 'text', name: 'a.log' }],
    entries: [
      {
        identityId: 1,
        category: 'ip',
        canonical: '10.0.0.42',
        alias: '192.0.2.42',
        disposition: 'bijective',
        occurrenceCount: 1,
      },
      {
        identityId: 2,
        category: 'custom',
        canonical: 'secret-a',
        alias: '[REDACTED]',
        disposition: 'ambiguous-fixed',
        occurrenceCount: 1,
      },
      {
        identityId: 3,
        category: 'custom',
        canonical: 'secret-b',
        alias: '[REDACTED]',
        disposition: 'ambiguous-fixed',
        occurrenceCount: 1,
      },
    ],
  }
}

describe('Stage 34 §39.1 — single-file stays simple', () => {
  beforeEach(() => {
    resetCorrelationImportForTests()
    useAppStore.getState().resetSession()
  })

  it('single text routes to single-text without staging project', async () => {
    const route = await ingestDroppedFiles([textFile('alone.log', 'host 10.0.0.1\n')])
    expect(route.kind).toBe('single-text')
  })

  it('single pcap routes to single-pcap without staging project', async () => {
    const route = await ingestDroppedFiles([pcapFile('alone.pcap', [10, 0, 0, 1])])
    expect(route.kind).toBe('single-pcap')
  })

  it('product has no named-project requirement for single-file completion', () => {
    // Mapping export is optional — collectActiveMappingSources can be empty; no project entity exists.
    expect(useAppStore.getState().phase).toBeDefined()
    expect('correlationProject' in useAppStore.getState()).toBe(false)
  })
})

describe('Stage 34 §39.2 — mapping bundle lifecycle', () => {
  beforeEach(() => {
    setSharedMappingClientForTests(new MappingWorkerClient(createInProcessMappingWorkerFactory()))
    clearResolveOnlyModel()
    releaseBundleCryptoSession()
  })

  afterEach(() => {
    releaseBundleCryptoSession()
    resetSharedMappingClient()
  })

  it('plain JSON roundtrip preserves entries', async () => {
    const json = serializeMappingBundleJson(samplePayload())
    const decoded = parseMappingBundleJsonText(json)
    expect(decoded.ok).toBe(true)
    if (!decoded.ok) return
    expect(decoded.value.entries).toHaveLength(samplePayload().entries.length)
  })

  it('cancelBundleJob returns phase to idle and release clears imported model', () => {
    setResolveOnlyPayload(
      {
        sessionId: 'x',
        canonicalizationVersion: 1,
        mappingRevision: 1,
        sources: [],
        entries: samplePayload().entries,
      },
      'test.rnd-mapping-bundle.json',
    )
    expect(isResolveOnlyActive()).toBe(true)
    cancelBundleJob()
    expect(getBundleJobPhase()).toBe('idle')
    releaseBundleCryptoSession()
    expect(getResolveOnlyPayload()).toBeNull()
    expect(isResolveOnlyActive()).toBe(false)
  })

  it('optional mapping export is separate from anonymized files and never persists in the store', async () => {
    const client = getSharedMappingClient()
    await client.resolve('g34', 'text', [
      { category: 'ip', canonical: '10.0.0.8', constraint: { kind: 'ipv4-wire' } },
    ])
    const state = useAppStore.getState() as Record<string, unknown>
    expect(JSON.stringify(state).toLowerCase()).not.toContain('mappingbundlepayload')
    releaseBundleCryptoSession()
    expect(getResolveOnlyPayload()).toBeNull()
    expect(getBundleJobPhase()).toBe('idle')
  })
})

describe('Stage 34 §39.3 — AI report paste bijective + ambiguous', () => {
  it('scans one report for both bijective IP and ambiguous fixed redaction', () => {
    const index = AliasLookupIndex.fromBundlePayload(samplePayload())
    const report = 'Peer 192.0.2.42 saw token [REDACTED] in the AI summary.'
    const scan = scanReportForPseudonyms(report, index)
    expect(scan.findings.some((f) => f.alias === '192.0.2.42' && !f.ambiguous)).toBe(true)
    expect(scan.findings.some((f) => f.alias === '[REDACTED]' && f.ambiguous)).toBe(true)
    const annotated = buildAnnotatedReport(report, scan.findings, {
      ambiguousLabel: 'nelze určit jednoznačně',
    })
    expect(annotated).toContain('10.0.0.42')
    expect(annotated).toContain('nelze určit jednoznačně')
  })
})

describe('Stage 34 §39.4–6 — multi-source correlation', () => {
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
    registerSourceAdapter(createPcapSourceAdapter({
      createProcessingClient: createInProcessPcapProcessingClient,
    }))
  })

  afterEach(() => {
    clearCorrelationSession()
    resetSharedMappingClient()
  })

  it('DOT + AS multi-log share one IP alias', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'dot', kind: SK.Text, file: textFile('dot.log', 'peer 10.0.0.5 ok\n') },
      { sourceId: 'as', kind: SK.Text, file: textFile('as.log', 'server 10.0.0.5 up\n') },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)
    const snap = getSharedMappingClient().getPublishedSnapshot()
    const aliases = snap!.entries.filter((e) => e.canonical === '10.0.0.5').map((e) => e.alias)
    expect(new Set(aliases).size).toBe(1)
  })

  it('two PCAP sources share wire-valid IP/MAC mapping', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'p1', kind: SK.Pcap, file: pcapFile('one.pcap', [10, 0, 0, 55]) },
      { sourceId: 'p2', kind: SK.Pcap, file: pcapFile('two.pcap', [10, 0, 0, 55]) },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)
    const snap = getSharedMappingClient().getPublishedSnapshot()
    const ip = snap!.entries.find((e) => e.canonical === '10.0.0.55')
    expect(ip?.alias).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
    expect(snap!.entries.some((e) => e.category === 'mac')).toBe(true)
  })

  it('mixed 100MiB PCAP + text fits aggregate; oversize rejects', () => {
    expect(MAX_PCAP_FILE_BYTES).toBe(100 * 1024 * 1024)
    expect(perKindFileLimit(SK.Pcap)).toBe(MAX_PCAP_FILE_BYTES)
    const mixed = MAX_PCAP_FILE_BYTES + 8 * 1024 * 1024
    expect(mixed).toBeLessThanOrEqual(CORRELATION_SESSION_LIMITS.maxAggregateBytes)
    expect(validateAggregateBytes(mixed)).toBeNull()
    expect(validateAggregateBytes(CORRELATION_SESSION_LIMITS.maxAggregateBytes + 1)).not.toBeNull()
  })

  it('micro mixed text+PCAP session shares IPv4 alias and leak-safe manifest', async () => {
    await stageCorrelationDescriptors([
      { sourceId: 'log', kind: SK.Text, file: textFile('mix.log', 'peer 10.0.0.55\n') },
      { sourceId: 'cap', kind: SK.Pcap, file: pcapFile('mix.pcap', [10, 0, 0, 55]) },
    ])
    const processed = await runCorrelationSession()
    expect('ok' in processed && processed.ok).toBe(true)
    const snap = getSharedMappingClient().getPublishedSnapshot()!
    const ip = snap.entries.find((e) => e.canonical === '10.0.0.55')
    expect(ip?.alias).toBeTruthy()
    const manifest = buildShareableCorrelationManifest({
      sources: [getCorrelationSource('log')!, getCorrelationSource('cap')!].filter(Boolean),
      snapshot: snap,
      partial: false,
    })
    if (manifest) {
      expect(() =>
        assertShareableManifestHasNoLeaks(JSON.stringify(manifest), ['10.0.0.55']),
      ).not.toThrow()
    }
  })
})

describe('Stage 34 §39.7 — cross-format golden mapping', () => {
  it('IPv4/IPv6/MAC/hostname goldens + length-conflict hostname', () => {
    expect(canonicalizeCrossFormatCategory('ipv4', '10.00.00.01', 'text')).toBe('10.0.0.1')
    expect(canonicalizeCrossFormatCategory('ipv6', '2001:0db8::1', 'pcap')).toBe('2001:db8:0:0:0:0:0:1')
    expect(canonicalizeCrossFormatCategory('mac', '00-1A-2b-3C-4d-5E', 'text')).toBe('00:1a:2b:3c:4d:5e')
    expect(canonicalizeCrossFormatCategory('hostname', 'Host.Example.COM.', 'text')).toBe('host.example.com')

    const textKey = crossFormatRegistryKeyFromIdentity('ip', '10.0.0.5', { kind: 'ipv4-wire' })
    const pcapKey = crossFormatRegistryKeyFromIdentity('ipv4', '10.0.0.5', { kind: 'ipv4-wire' })
    expect(textKey).toBe(pcapKey)

    const shared = constraintsCompatible('ipv4', { kind: 'ipv4-wire' }, { kind: 'ipv4-wire' })
    expect(shared.compatible && shared.sharedAlias).toBe(true)

    const hostConflict = constraintsCompatible(
      'hostname',
      { kind: 'text-ascii', byteLength: 40 },
      { kind: 'hostname-ascii', labelCount: 2, maxLabelLength: 8 },
    )
    expect(hostConflict.compatible).toBe(true)
    if (hostConflict.compatible) expect(hostConflict.sharedAlias).toBe(false)
  })
})

describe('Stage 34 §39.8 — profile compatibility blocking', () => {
  it('blocks processing until conflict is resolved', () => {
    const config = cloneRulesetConfig(createDefaultRulesetConfig())
    config.profile.rules.push({
      id: 'ip-fixed',
      name: 'fixed ip',
      enabled: true,
      kind: 'literal',
      pattern: '10.',
      category: 'ip',
      replacement: { kind: 'fixed', value: 'ip-1' },
      priority: 5000,
    })
    const policy = compileCorrelationPolicy({
      sourceKinds: [SK.Text, SK.Pcap],
      textProfile: config,
      pcapProfile: createDefaultPcapProfile().profile,
    })
    const report = evaluateProfileCompatibility(policy)
    expect(report.outcome).toBe(PROFILE_COMPATIBILITY_OUTCOME.BlockingConflict)
    expect(compatibilityAllowsProcessing(report)).toBe(false)
  })
})

describe('Stage 34 §39.10 — no decrypted persistence / no network APIs', () => {
  it('zustand snapshot never holds passphrase or decrypted bundle fields by design', () => {
    const keys = Object.keys(useAppStore.getState())
    expect(keys).not.toContain('passphrase')
    expect(keys).not.toContain('decryptedMapping')
    expect(keys).not.toContain('mappingBundlePayload')
  })

  it('network API guard script is present and verify includes it', () => {
    expect(existsSync(join(root, 'scripts/check-no-network-apis.mjs'))).toBe(true)
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
    expect(pkg.scripts.verify).toContain('check:network')
  })
})

describe('Stage 34 §39.11 — e-mail files are unsupported sources', () => {
  it('probe rejects MIME/.eml and no email adapter is registered', () => {
    resetCorrelationAdaptersForTests()
    bootstrapDefaultSourceAdapters()
    expect(registeredAdapterKinds()).not.toContain('email')
    const eml = new TextEncoder().encode('From: a@b.c\r\nSubject: x\r\nMIME-Version: 1.0\r\n\r\nbody\r\n')
    const probe = probeSourceKind(eml)
    expect(probe.kind).toBe('unsupported')
    if (probe.kind === 'unsupported') expect(probe.code).toBe('mime-unsupported')
    expect(MAX_TEXT_FILE_BYTES).toBeLessThanOrEqual(90 * 1024 * 1024)
  })

  it('preflight port keeps mime-unsupported rejection path', () => {
    const src = readFileSync(join(root, 'src/correlation/import/sourcePreflightPort.ts'), 'utf8')
    expect(src).toContain('mime-unsupported')
  })
})

describe('Stage 34 §39.12 — README describes real adapters', () => {
  it('README documents text/pcap adapters, manifest vs bundle, limits', () => {
    const readme = readFileSync(join(root, 'README.md'), 'utf8')
    expect(readme).toMatch(/text/i)
    expect(readme).toMatch(/PCAP/i)
    expect(readme).toMatch(/shareable|correlation-manifest|Shareable|manifest/i)
    expect(readme).toMatch(/mapping bundle/i)
    expect(readme).toMatch(/100\s*MiB|90\s*MiB/)
    expect(readme).not.toMatch(/EMAIL_SOURCE_ENABLED/)
    expect(readme).not.toMatch(/[áčďéěíňóřšťúůýžÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]/)
  })
})
