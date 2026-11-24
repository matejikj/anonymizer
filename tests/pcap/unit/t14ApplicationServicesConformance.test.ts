/**
 * T14 — application services over T-01 kernel (no second registry).
 */
import { describe, expect, it } from 'vitest'
import {
  APPLICATION_HANDLER_ORDER,
  assertEncryptedClassification,
  assertFieldPolicyDictionary,
  categoryDescriptor,
  createPayloadTimeSession,
  HTTP_FIELD_DICTIONARY,
  MEDIA_DESCRIPTION_FACT,
  OPAQUE_ID_CATEGORY,
  validateEncryptedClassification,
  validateFieldPolicyDictionary,
} from '../../../src/pcap/kernel'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { assertMappingDomainsComplete } from '../../../src/pcap/anonymization/mappingDomainRegistry'
import { canonicalizePcapIdentity } from '../../../src/mapping/pcapCanonical'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { buildEthIpTcp } from '../fixtures/voipCorpus'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function envelope(data: Uint8Array, index: number, epochSeconds: bigint): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: {
      ticks: epochSeconds * 1_000_000n,
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

describe('T14 application services — contracts', () => {
  it('does not introduce a second application handler registry', () => {
    expect(APPLICATION_HANDLER_ORDER.map((h) => h.id)).toContain('http')
    expect(APPLICATION_HANDLER_ORDER.map((h) => h.id)).toContain('sip')
  })

  it('registers opaque-id with domain + length-stable alias ≠ original', () => {
    assertMappingDomainsComplete()
    expect(canonicalizePcapIdentity('opaque-id', 'device-abc-001')).toBe('device-abc-001')
    const mapping = new SessionMapping(
      {
        ip: 'topology-preserving',
        mac: 'locally-administered',
        timestamps: 'relative',
        ephemeralPorts: 'preserve',
        contentSignalingPorts: 'preserve',
        vlan: 'map',
      },
      { seed: 't14-opaque' },
    )
    const alias = mapping.map('opaque-id', 'device-abc-001')
    expect(alias).toHaveLength('device-abc-001'.length)
    expect(alias).not.toBe('device-abc-001')
    expect(mapping.map('opaque-id', 'device-abc-001')).toBe(alias)
    expect(categoryDescriptor(OPAQUE_ID_CATEGORY).domain?.kind).toBe('opaque-id')
  })

  it('rejects secret→preserve and accepts HTTP field dictionary', () => {
    const bad = validateFieldPolicyDictionary([
      {
        variant: 'x',
        fieldPath: 'secret',
        valueType: 'token',
        identityRole: 'secret',
        diagnosticAction: 'preserve',
        highPrivacyAction: 'mask',
      },
    ])
    expect(bad.some((e) => e.code === 'secret-preserve-forbidden')).toBe(true)
    expect(() => assertFieldPolicyDictionary(HTTP_FIELD_DICTIONARY)).not.toThrow()
  })

  it('requires proven confidentiality for encrypted classification', () => {
    expect(
      validateEncryptedClassification({
        protocolId: 'tls',
        variant: '',
        phase: 'application-data',
        confidentialityProven: true,
      })?.code,
    ).toBe('missing-variant')
    expect(
      validateEncryptedClassification({
        protocolId: 'tls',
        variant: 'tls1.2-appdata',
        phase: 'application-data',
        confidentialityProven: false,
      })?.code,
    ).toBe('confidentiality-unproven')
    expect(() =>
      assertEncryptedClassification({
        protocolId: 'tls',
        variant: 'tls1.2-appdata',
        phase: 'application-data',
        confidentialityProven: true,
      }),
    ).not.toThrow()
    expect(MEDIA_DESCRIPTION_FACT).toBe('media-description')
  })

  it('PayloadTimeSession shifts HTTP-date with capture Δ (unit-independent)', () => {
    const session = createPayloadTimeSession('relative', 't14-time-seed')
    const captureEpoch = 1_700_000_000n
    session.bindCaptureReference({
      ticks: captureEpoch * 1_000_000n,
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    })
    const original = 'Wed, 15 Nov 2023 08:12:31 GMT'
    const rewrite = session.rewriteHttpDateFixedLength(original)
    expect(rewrite.kind).toBe('shifted')
    if (rewrite.kind !== 'shifted') return
    expect(rewrite.text).toHaveLength(original.length)
    expect(rewrite.text).not.toBe(original)
    expect(rewrite.text.endsWith(' GMT')).toBe(true)
    // Unparseable → mask
    expect(session.rewriteHttpDateFixedLength('not-a-date').kind).toBe('mask')
  })

  it(`bumps PCAP_ENGINE_VERSION for Date rewrite (${PCAP_ENGINE_VERSION})`, () => {
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T14 HTTP Date — deferred resolve', () => {
  it('rewrites Date when DeferredPatchContext carries PayloadTimeSession', async () => {
    const { sanitizePacket } = await import('../../../src/pcap/sanitize/engine')
    const { DIAGNOSTIC_POLICY } = await import('../../../src/pcap/profile/presets')
    const { SnapshotMappingAdapter } = await import('../../../src/pcap/plan/snapshotMappingAdapter')
    const { FingerprintSession } = await import('../../../src/pcap/anonymization/fingerprintSession')
    const { derivePlanEntropySeed } = await import('../../../src/pcap/export/planSnapshot')
    const date = 'Wed, 15 Nov 2023 08:12:31 GMT'
    const http = latin1(`GET /x HTTP/1.1\r\nHost: app.example.com\r\nDate: ${date}\r\n\r\n`)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1, http)
    const seed = derivePlanEntropySeed('t14-deferred')
    const payloadTime = createPayloadTimeSession('relative', seed)
    payloadTime.bindCaptureReference({
      ticks: 1_700_000_000n * 1_000_000n,
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    })
    const mapping = new SnapshotMappingAdapter({
      generationId: 'g',
      sourceId: 's',
      mappingRevision: 1,
      createdAt: 0,
      entries: [],
    })
    const result = sanitizePacket(
      {
        index: 0,
        data: frame,
        capturedLength: frame.length,
        originalLength: frame.length,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      mapping,
      { deferPatchResolution: true },
    )
    expect(result.resolvePatches).toBeTypeOf('function')
    const patches = result.resolvePatches!({
      mapping,
      fingerprints: new FingerprintSession(seed),
      payloadTime,
    })
    const datePatch = patches.find((p) => {
      const s = new TextDecoder('latin1').decode(p.data)
      return s.includes('GMT') || s.includes('*')
    })
    expect(datePatch).toBeTruthy()
    const text = new TextDecoder('latin1').decode(datePatch!.data)
    expect(text).not.toBe(date)
    expect(text.includes('*')).toBe(false)
    expect(text).toMatch(/^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/)
  })
})

describe('T14 HTTP Date — export pipeline', () => {
  it('shifts Date/Last-Modified and never leaks originals (diagnostic + high-privacy)', () => {
    const date = 'Wed, 15 Nov 2023 08:12:31 GMT'
    const lastMod = 'Tue, 14 Nov 2023 10:00:00 GMT'
    const http = latin1(
      `GET /x HTTP/1.1\r\nHost: app.example.com\r\nDate: ${date}\r\nLast-Modified: ${lastMod}\r\nCookie: sess=secret\r\n\r\n`,
    )
    const pkt = envelope(
      buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 1, http),
      0,
      1_700_000_000n,
    )

    for (const level of ['diagnostic', 'high-privacy'] as const) {
      const result = runExportPipeline([pkt], level, 't14-http-date.pcap', `t14-http-${level}`, {
        mappingSeed: 't14-http-date',
      })
      expect(result.discovery.packetDiscovery[0]?.frozenPlan).toBeDefined()
      expect(result.built.packets.length).toBe(1)
      const exported = result.built.packets[0]!.data
      const text = new TextDecoder('latin1').decode(exported)
      // Debug: surface Date header span from plan patches when rewrite fails closed.
      const dateHeader = text.match(/Date: ([^\r\n]+)/)?.[1] ?? ''
      expect(text.includes(date)).toBe(false)
      expect(text.includes(lastMod)).toBe(false)
      expect(text.includes('sess=secret')).toBe(false)
      expect(dateHeader.includes('*'), `Date header was masked not shifted: ${dateHeader}`).toBe(false)
      expect(text).toMatch(/Date: [A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT/)
      expect(result.plan.engineVersion).toBe('2.37.0')
    }
  })
})
