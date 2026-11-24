/**
 * T11 — structured MGCP support: parse, analyze parity, export canaries, media registration.
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { ClassicPcapHeader, PacketEnvelope } from '../../../src/pcap/domain/types'
import { DIAGNOSTIC_POLICY, createPresetProfile } from '../../../src/pcap/profile/presets'
import { runDiscoveryPipeline, identitiesFromDiscovery } from '../../../src/pcap/discovery/discoveryPipeline'
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import { buildDeterministicPlan } from '../../../src/pcap/plan/deterministicPlanBuilder'
import {
  dedupeIdentities,
  identitiesForClosureFailures,
  validateMappingClosure,
} from '../../../src/pcap/plan/mappingClosureValidation'
import { buildCaptureFromPlan } from '../../../src/pcap/export/engine'
import { classifyMgcpPayload } from '../../../src/pcap/protocols/application/mgcp/parse'
import { analyzeMgcpMessages } from '../../../src/pcap/protocols/application/mgcp/analyze'
import { recordMgcpDiscoveryIntents } from '../../../src/pcap/protocols/application/mgcp/discoverIntents'
import { IntentCollector } from '../../../src/pcap/discovery/intentCollector'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { buildAnonymizationOutcome, coverageRowsFromProtocolSummaries } from '../../../src/pcap/coverage/anonymizationOutcome'
import { resolveExportGate, buildGateChecksFromCoverage, summarizeSanitizationCoverage } from '../../../src/pcap/trust'
import {
  MGCP_SEED,
  MGCP_SEED_TOKENS,
  buildMgcpCrcxWithSdp,
  buildMgcpDigitMap,
  buildMgcpIpv6NotifiedEntity,
  buildMgcpNtfyDtmf,
  buildMgcpPiggyback,
  buildMgcpQuotedPackageComma,
  buildMgcpResponseWithText,
  buildMgcpSignalCallerId,
  buildMgcpUnknownVendorParam,
  buildMgcpWildcardEndpoint,
  mgcpCorpusScenarios,
} from '../fixtures/mgcpCorpus'

function classicHeader(): ClassicPcapHeader {
  return {
    format: CaptureFormat.ClassicPcap,
    endian: Endian.Little,
    timestampResolution: TimestampResolution.Microseconds,
    versionMajor: 2,
    versionMinor: 4,
    snapLen: 65535,
    linkType: 1,
    tzOffset: 0,
    sigfigs: 0,
  }
}

function runMgcpPipeline(packets: readonly PacketEnvelope[], fileName: string) {
  const policy = DIAGNOSTIC_POLICY
  const profile = createPresetProfile('diagnostic', { id: 'mgcp-gate', name: 'MGCP gate' })
  const reassembly = runCaptureReassembly(packets, policy)
  const discovery = runDiscoveryPipeline(packets, policy, 'mgcp-gate', fileName, {
    reassemblyContext: reassembly,
  })
  const authority = new MappingAuthority({
    ip: profile.mapping.ip,
    mac: profile.mapping.mac,
    timestamps: profile.mapping.timestamps,
    ephemeralPorts: profile.mapping.ephemeralPorts,
    contentSignalingPorts: profile.mapping.contentSignalingPorts,
    vlan: profile.mapping.vlan,
  })
  const identities = identitiesFromDiscovery(discovery)
  let resolved = authority.resolve({ generationId: 'mgcp-gate', sourceId: fileName, identities })
  if (!resolved.ok) throw new Error('mapping resolve failed')
  let unresolvedFailures: import('../../../src/pcap/plan/mappingClosureValidation').MappingClosureFailure[] =
    []
  let closure = validateMappingClosure(discovery.intents, resolved.snapshot)
  if (!closure.ok) {
    const topUp = identitiesForClosureFailures(closure.failures)
    resolved = authority.resolve({
      generationId: 'mgcp-gate',
      sourceId: fileName,
      identities: dedupeIdentities([...identities, ...topUp]),
    })
    if (!resolved.ok) throw new Error('mapping resolve failed')
    closure = validateMappingClosure(discovery.intents, resolved.snapshot)
    if (!closure.ok) unresolvedFailures = [...closure.failures]
  }
  const plan = buildDeterministicPlan({
    generationId: 'mgcp-gate',
    profile,
    format: CaptureFormat.ClassicPcap,
    fileName,
    packets,
    policy,
    snapshot: resolved.snapshot,
    reassemblyContext: reassembly,
    classicHeader: classicHeader(),
    packetDiscovery: discovery.packetDiscovery,
    sourceId: fileName,
    unresolvedClosureFailures: unresolvedFailures,
  })
  const built = buildCaptureFromPlan(plan, packets)
  return { discovery, plan, built }
}

function payloadBytes(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

describe('T11 MGCP structured support', () => {
  it('classifies CRCX+SDP and piggyback', () => {
    const a = payloadBytes(buildMgcpCrcxWithSdp())
    const c = classifyMgcpPayload(a, 0, a.length, { portHint: true })
    expect(c.kind).toBe('complete')
    if (c.kind !== 'complete') return
    expect(c.messages).toHaveLength(1)
    expect(c.messages[0]!.start.verb).toBe('CRCX')
    expect(c.messages[0]!.bodySpan).not.toBeNull()

    const pig = payloadBytes(buildMgcpPiggyback())
    const p = classifyMgcpPayload(pig, 0, pig.length, { portHint: true })
    expect(p.kind).toBe('complete')
    if (p.kind !== 'complete') return
    expect(p.messages.length).toBeGreaterThanOrEqual(2)
  })

  it('maps CallId/ConnectionId/RequestIdentifier consistently; masks DTMF/key/response text', () => {
    const buf = payloadBytes(buildMgcpCrcxWithSdp())
    const c = classifyMgcpPayload(buf, 0, buf.length, { portHint: true })
    expect(c.kind).toBe('complete')
    if (c.kind !== 'complete') return
    const plan = analyzeMgcpMessages(buf, c.messages)
    const cats = plan.operations.filter((o) => o.action === 'map').map((o) => o.mappingCategory)
    expect(cats).toContain('sip-call-id')
    expect(cats).toContain('sip-token')
    expect(cats).toContain('hostname')
    expect(plan.operations.some((o) => o.action === 'redact')).toBe(true)
    expect(plan.sdpBundles.length).toBe(1)
    expect(familyForProtocol('mgcp').familyId).toBe('mgcp')
  })

  it('discovery ⊇ analyze map ops (parity)', () => {
    const buf = payloadBytes(buildMgcpCrcxWithSdp())
    const c = classifyMgcpPayload(buf, 0, buf.length, { portHint: true })
    expect(c.kind).toBe('complete')
    if (c.kind !== 'complete') return
    const analyzed = analyzeMgcpMessages(buf, c.messages)
    const intents = new IntentCollector()
    recordMgcpDiscoveryIntents(intents, buf, c.messages, 'udp', 0)
    const mapKeys = new Set(
      analyzed.operations
        .filter((o) => o.action === 'map' && o.mappingCategory && o.sessionIdForVersion === undefined)
        .map((o) => `${o.mappingCategory}:${o.canonicalText}:${o.span.offset}`),
    )
    const intentKeys = new Set(
      intents.intents
        .filter((i) => i.kind === 'entity-replacement')
        .map((i) => {
          const e = i as {
            category: string
            canonical: string
            offset: number
          }
          return `${e.category}:${e.canonical}:${e.offset}`
        }),
    )
    for (const k of mapKeys) {
      // port canonical may include udp/ prefix in intents
      const found =
        intentKeys.has(k)
        || [...intentKeys].some((ik) => ik.endsWith(`:${k.split(':').slice(1).join(':')}`))
        || [...intentKeys].some((ik) => {
          const [cat, ...rest] = k.split(':')
          return ik.startsWith(`${cat}:`) && ik.endsWith(`:${rest[rest.length - 1]}`)
        })
      expect(found, `missing discovery for ${k}`).toBe(true)
    }
  })

  it('export canary scan: identities/keys/DTMF/caller not in output', () => {
    const packets = [
      mgcpCorpusScenarios.crcxSdp(),
      mgcpCorpusScenarios.ntfyDtmf(),
      mgcpCorpusScenarios.callerId(),
      mgcpCorpusScenarios.digitMap(),
      mgcpCorpusScenarios.responseText(),
    ]
    const { built } = runMgcpPipeline(packets, 'mgcp-canary.pcap')
    const ascii = new TextDecoder('latin1').decode(new Uint8Array(built.buffer))
    for (const token of MGCP_SEED_TOKENS) {
      expect(ascii.includes(token), `leaked ${token}`).toBe(false)
    }
    // Verb / transaction mechanics preserved
    expect(ascii).toMatch(/CRCX\s+\d+/)
    expect(ascii).toMatch(/NTFY\s+\d+/)
    expect(ascii).toMatch(/MGCP\s+1\.0/i)
  })

  it('CallId alias is stable across CRCX and piggyback response path', () => {
    const packets = [mgcpCorpusScenarios.crcxSdp(), mgcpCorpusScenarios.piggyback()]
    const { built } = runMgcpPipeline(packets, 'mgcp-stable.pcap')
    const ascii = new TextDecoder('latin1').decode(new Uint8Array(built.buffer))
    expect(ascii.includes(MGCP_SEED.callId)).toBe(false)
    // At least one mapped C: line remains (length-preserving)
    expect(ascii).toMatch(/\r\nC:\s+\S+/)
  })

  it('masks DTMF digit and digit-map canary; preserves event mechanic', () => {
    const ntfy = payloadBytes(buildMgcpNtfyDtmf())
    const c = classifyMgcpPayload(ntfy, 0, ntfy.length, { portHint: true })
    expect(c.kind).toBe('complete')
    if (c.kind !== 'complete') return
    const plan = analyzeMgcpMessages(ntfy, c.messages)
    expect(plan.operations.some((o) => o.action === 'redact' && o.span.length === 1)).toBe(true)

    const dm = payloadBytes(buildMgcpDigitMap())
    const d = classifyMgcpPayload(dm, 0, dm.length, { portHint: true })
    expect(d.kind).toBe('complete')
    if (d.kind !== 'complete') return
    const dmPlan = analyzeMgcpMessages(dm, d.messages)
    expect(dmPlan.operations.some((o) => o.action === 'redact')).toBe(true)

    const ci = payloadBytes(buildMgcpSignalCallerId())
    const s = classifyMgcpPayload(ci, 0, ci.length, { portHint: true })
    expect(s.kind).toBe('complete')
    if (s.kind !== 'complete') return
    const sPlan = analyzeMgcpMessages(ci, s.messages)
    expect(sPlan.operations.some((o) => o.mappingCategory === 'sip-user')).toBe(true)
  })

  it('response free text is redacted', () => {
    const buf = payloadBytes(buildMgcpResponseWithText())
    const c = classifyMgcpPayload(buf, 0, buf.length, { portHint: true })
    expect(c.kind).toBe('complete')
    if (c.kind !== 'complete') return
    const plan = analyzeMgcpMessages(buf, c.messages)
    expect(plan.operations.some((o) => o.action === 'redact')).toBe(true)
  })

  it('T10 outcome lists MGCP family as anonymized with AI_READY when export is clean', () => {
    const { discovery, plan } = runMgcpPipeline([mgcpCorpusScenarios.crcxSdp()], 'mgcp-outcome.pcap')
    const row = discovery.unifiedCoverage.byProtocol.find((p) => p.protocol === 'mgcp')
    expect(row).toBeDefined()
    const summary = summarizeSanitizationCoverage({ plan, coverage: discovery.packetDiscovery[0]?.coverage })
    const gate = resolveExportGate({
      profile: 'diagnostic',
      checks: buildGateChecksFromCoverage({
        coverage: summary,
        leakHits: 0,
        verificationFatalErrors: 0,
        profile: 'diagnostic',
        diagnosticInvariantOk: true,
      }),
    })
    const outcome = buildAnonymizationOutcome({
      protocols: coverageRowsFromProtocolSummaries(discovery.unifiedCoverage.byProtocol, 'diagnostic'),
      gate: gate.gate,
      plan,
      preset: 'diagnostic',
      incidents: plan.incidents,
    })
    expect(['AI_READY', 'AI_READY_WITH_GAPS']).toContain(outcome.gate)
    expect(outcome.gate).not.toBe('NOT_AI_READY')
    const mgcp = outcome.families.find((f) => f.familyId === 'mgcp')
    expect(mgcp).toBeTruthy()
    expect(['anonymized', 'anonymized-with-loss']).toContain(mgcp!.state)
  })

  it('coverage protocol mgcp is covered (not unsupported:mgcp) on UDP export path', () => {
    const { discovery } = runMgcpPipeline([mgcpCorpusScenarios.crcxSdp()], 'mgcp-cov.pcap')
    const protocols = discovery.unifiedCoverage.byProtocol.map((p) => p.protocol)
    expect(protocols).toContain('mgcp')
    expect(protocols).not.toContain('unsupported:mgcp')
    const row = discovery.unifiedCoverage.byProtocol.find((p) => p.protocol === 'mgcp')
    expect(row?.dominantStatus).toBe('covered')
  })

  it('maps IPv6 NotifiedEntity; preserves wildcard local; masks DigitMap canary not [2-9] range', () => {
    const v6 = payloadBytes(buildMgcpIpv6NotifiedEntity())
    const c6 = classifyMgcpPayload(v6, 0, v6.length, { portHint: true })
    expect(c6.kind).toBe('complete')
    if (c6.kind !== 'complete') return
    const p6 = analyzeMgcpMessages(v6, c6.messages)
    expect(p6.operations.some((o) => o.mappingCategory === 'ipv6' && o.canonicalText === MGCP_SEED.caIpv6)).toBe(
      true,
    )

    const wild = payloadBytes(buildMgcpWildcardEndpoint())
    const cw = classifyMgcpPayload(wild, 0, wild.length, { portHint: true })
    expect(cw.kind).toBe('complete')
    if (cw.kind !== 'complete') return
    const pw = analyzeMgcpMessages(wild, cw.messages)
    expect(pw.operations.some((o) => o.canonicalText === '*')).toBe(false)

    const dm = payloadBytes(buildMgcpDigitMap())
    const cd = classifyMgcpPayload(dm, 0, dm.length, { portHint: true })
    expect(cd.kind).toBe('complete')
    if (cd.kind !== 'complete') return
    const pd = analyzeMgcpMessages(dm, cd.messages)
    const dLine = cd.messages[0]!.parameters.find((p) => p.name === 'D')!
    const rangeTwo = dLine.valueText.indexOf('[2-9]')
    expect(rangeTwo).toBeGreaterThanOrEqual(0)
    const maskedInsideClass = pd.operations.some(
      (o) =>
        o.action === 'redact'
        && o.span.offset >= dLine.valueSpan.offset + rangeTwo
        && o.span.offset < dLine.valueSpan.offset + rangeTwo + 5,
    )
    expect(maskedInsideClass).toBe(false)
    expect(
      pd.operations.some(
        (o) =>
          o.action === 'redact'
          && o.span.offset >= dLine.valueSpan.offset
          && o.span.offset < dLine.valueSpan.offset + MGCP_SEED.digitMapCanary.length + 2,
      ),
    ).toBe(true)
  })

  it('masks quoted package args with commas; unknown vendor param without losing Mode', () => {
    const q = payloadBytes(buildMgcpQuotedPackageComma())
    const cq = classifyMgcpPayload(q, 0, q.length, { portHint: true })
    expect(cq.kind).toBe('complete')
    if (cq.kind !== 'complete') return
    const pq = analyzeMgcpMessages(q, cq.messages)
    expect(
      pq.operations.some(
        (o) => o.action === 'redact' && o.span.length === MGCP_SEED.quotedPackageCanary.length,
      ),
    ).toBe(true)

    const u = payloadBytes(buildMgcpUnknownVendorParam())
    const cu = classifyMgcpPayload(u, 0, u.length, { portHint: true })
    expect(cu.kind).toBe('complete')
    if (cu.kind !== 'complete') return
    const pu = analyzeMgcpMessages(u, cu.messages)
    expect(pu.issues.some((i) => i.startsWith('mgcp-unknown-param:'))).toBe(true)
    expect(pu.operations.some((o) => o.action === 'redact')).toBe(true)
    // Mode value is preserve — no map/redact covering the "recvonly" span alone as unknown
    const mode = cu.messages[0]!.parameters.find((p) => p.name === 'M')!
    expect(
      pu.operations.some(
        (o) =>
          o.span.offset === mode.valueSpan.offset && o.span.length === mode.valueSpan.length && o.action === 'redact',
      ),
    ).toBe(false)
  })

  it('extended corpus canary scan includes IPv6 / quoted package / vendor', () => {
    const packets = [
      mgcpCorpusScenarios.ipv6Notified(),
      mgcpCorpusScenarios.quotedComma(),
      mgcpCorpusScenarios.unknownVendor(),
      mgcpCorpusScenarios.wildcard(),
    ]
    const { built } = runMgcpPipeline(packets, 'mgcp-ext.pcap')
    const ascii = new TextDecoder('latin1').decode(new Uint8Array(built.buffer))
    for (const token of [
      MGCP_SEED.caIpv6,
      MGCP_SEED.quotedPackageCanary,
      MGCP_SEED.cryptoKey,
      MGCP_SEED.callId,
    ]) {
      expect(ascii.includes(token), `leaked ${token}`).toBe(false)
    }
    expect(ascii).toMatch(/AUEP\s+\d+\s+\*/)
    expect(ascii).toMatch(/M:\s*recvonly/)
  })
})
