/**
 * Enterprise step 6 — ports (semantic/IANA), checksum sidecard, crypto-integrity.
 */

import { describe, expect, it } from 'vitest'
import {
  classifyPort,
  ianaPortClass,
  isPreservedServicePort,
  isSystemPort,
  semanticPortRole,
  shouldPreservePort,
  SYSTEM_PORT_MAX,
} from '../../../src/pcap/anonymization/portPolicy'
import { SessionMapping, DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping'
import { recomputeChecksums } from '../../../src/pcap/checksums/engine'
import {
  ORIGINAL_CHECKSUM_STATES,
  classifyOriginalChecksumState,
} from '../../../src/pcap/checksums/types'
import { resolveCryptographicIntegrity, CRYPTO_INTEGRITY_ISSUE } from '../../../src/pcap/trust'
import { buildExportReport } from '../../../src/pcap/export/report'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'
import { emptyChecksumCounts, emptyOriginalStateCounts } from '../../../src/pcap/checksums/types'
import { buildPrivacyReport } from '../../../src/pcap/privacy'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets'
import { hasRtcpMux } from '../../../src/pcap/protocols/application/sdp/attributes'
import { buildSdpMediaEndpoints } from '../../../src/pcap/protocols/application/sdp/mediaModel'
import { parseSdp } from '../../../src/pcap/protocols/application/sdp/parser'

function emptyPlan(): PcapPlanSnapshot {
  return {
    generationId: 'g-e6',
    pcapLevel: 'diagnostic',
    profileId: 'pcap-diagnostic',
    profileHash: 'hash',
    format: CaptureFormat.ClassicPcap,
    fileName: 'e6.pcap',
    engineVersion: 'test',
    packets: [],
    droppedPacketNumbers: [],
    timestamps: 'relative',
    timestampAnchorSeed: 'seed',
    changeCategoryTotals: {
      mapped: 0,
      redacted: 0,
      'masked-content': 0,
      'preserved-encrypted': 0,
      'preserved-for-diagnostics': 0,
      'user-requested-drop': 0,
      blocked: 0,
    },
    maskedByteCount: 0,
    dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
    dropsByProtocol: {},
  }
}

function buildEthIpUdp(src: number[], dst: number[], srcPort: number, dstPort: number, csum = 0): Uint8Array {
  const buf = new Uint8Array(42)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  buf[16] = 0
  buf[17] = 28
  buf[23] = 17
  buf.set(src, 26)
  buf.set(dst, 30)
  buf[34] = (srcPort >> 8) & 0xff
  buf[35] = srcPort & 0xff
  buf[36] = (dstPort >> 8) & 0xff
  buf[37] = dstPort & 0xff
  buf[38] = 0
  buf[39] = 8
  buf[40] = (csum >> 8) & 0xff
  buf[41] = csum & 0xff
  return buf
}

describe('enterprise step 6 — port policy', () => {
  it('preserves SIP 5060 by semantic role, not because <1024', () => {
    expect(ianaPortClass(5060)).toBe('user-registered')
    expect(5060).toBeGreaterThan(SYSTEM_PORT_MAX)
    expect(isPreservedServicePort(5060)).toBe(true)
    expect(shouldPreservePort(5060)).toBe(true)
    expect(semanticPortRole(5060)).toBe('signaling')
    expect(classifyPort(5060)).toBe('registered-service')
  })

  it('does not auto-preserve obscure system ports solely for being <1024', () => {
    // Port 7 (echo) is system-class but not in the semantic service catalog.
    expect(isSystemPort(7)).toBe(true)
    expect(isPreservedServicePort(7)).toBe(false)
    expect(shouldPreservePort(7)).toBe(false)
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' })
    const mapped = mapping.map('port', 'tcp/7')
    expect(mapped).not.toBe('tcp/7')
  })

  it('keeps DNS/HTTPS fixed under permute', () => {
    const mapping = new SessionMapping({ ...DEFAULT_MAPPING_CONFIG, ephemeralPorts: 'permute' })
    expect(mapping.map('port', 'udp/53')).toBe('udp/53')
    expect(mapping.map('port', 'tcp/443')).toBe('tcp/443')
  })
})

describe('enterprise step 6 — SDP RTCP port', () => {
  it('respects a=rtcp-mux and does not invent p+1 without signal', () => {
    const mux = new TextEncoder().encode(
      'v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n'
      + 'm=audio 4000 RTP/AVP 0\r\na=rtcp-mux\r\n',
    )
    const muxParsed = parseSdp(mux)
    expect(muxParsed.kind).toBe('complete')
    if (muxParsed.kind !== 'complete') return
    expect(hasRtcpMux(muxParsed.session.media[0]!.attributes)).toBe(true)
    const muxEp = buildSdpMediaEndpoints(muxParsed.session, mux)
    expect(muxEp[0]?.rtcpPort).toBe(4000)

    const bare = new TextEncoder().encode(
      'v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n'
      + 'm=audio 4000 RTP/AVP 0\r\n',
    )
    const bareParsed = parseSdp(bare)
    expect(bareParsed.kind).toBe('complete')
    if (bareParsed.kind !== 'complete') return
    const bareEp = buildSdpMediaEndpoints(bareParsed.session, bare)
    expect(bareEp[0]?.rtcpPort).toBeNull()

    const explicit = new TextEncoder().encode(
      'v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n'
      + 'm=audio 4000 RTP/AVP 0\r\na=rtcp:4005\r\n',
    )
    const exParsed = parseSdp(explicit)
    expect(exParsed.kind).toBe('complete')
    if (exParsed.kind !== 'complete') return
    const exEp = buildSdpMediaEndpoints(exParsed.session, explicit)
    expect(exEp[0]?.rtcpPort).toBe(4005)
  })
})

describe('enterprise step 6 — checksum sidecard', () => {
  it('records NOT_PRESENT for UDP zero without rewriting', () => {
    const data = buildEthIpUdp([192, 168, 1, 1], [10, 0, 0, 1], 4000, 53, 0)
    const report = recomputeChecksums(data, {
      linkType: 1,
      capturedLen: data.length,
      originalLen: data.length,
      patches: [{ offset: 26, data: new Uint8Array([10, 254, 0, 1]) }],
      originalData: data.slice(),
    })
    const udp = report.fields.find((f) => f.layer === 'udp')
    expect(udp?.disposition).toBe('preserved-zero')
    expect(udp?.originalState).toBe('NOT_PRESENT')
    expect(data[40]).toBe(0)
    expect(data[41]).toBe(0)
    expect(report.originalStateCounts?.NOT_PRESENT).toBeGreaterThan(0)
  })

  it('records OFFLOADED_PARTIAL for TCP zero checksum and still recomputes after IP map', () => {
    const buf = new Uint8Array(54)
    buf[12] = 0x08
    buf[13] = 0x00
    buf[14] = 0x45
    buf[16] = 0
    buf[17] = 40
    buf[23] = 6
    buf.set([192, 168, 1, 1], 26)
    buf.set([10, 0, 0, 1], 30)
    buf[34] = 0x13
    buf[35] = 0x88 // 5000
    buf[36] = 0
    buf[37] = 80
    buf[46] = 0x50 // data offset
    // TCP checksum left 0 → offload suspected
    const original = buf.slice()
    const patches = [{ offset: 26, data: new Uint8Array([10, 254, 1, 1]) }]
    buf.set(patches[0]!.data, 26)
    const report = recomputeChecksums(buf, {
      linkType: 1,
      capturedLen: buf.length,
      originalLen: buf.length,
      patches,
      originalData: original,
    })
    const tcp = report.fields.find((f) => f.layer === 'tcp')
    expect(tcp?.originalState).toBe('OFFLOADED_PARTIAL')
    expect(tcp?.disposition).toBe('recomputed')
    expect(tcp?.outputValue).not.toBe(0)
  })

  it('exposes originalState vocabulary', () => {
    expect(ORIGINAL_CHECKSUM_STATES).toContain('OFFLOADED_PARTIAL')
    expect(
      classifyOriginalChecksumState({
        present: true,
        truncated: true,
        verifiedValid: null,
      }),
    ).toBe('NOT_VERIFIABLE_TRUNCATED')
  })
})

describe('enterprise step 6 — cryptographic_integrity', () => {
  it('marks MODIFIED for TLS handshake coverage and SIP Identity issues', () => {
    expect(
      resolveCryptographicIntegrity({
        coverage: [{ protocol: 'tls-clienthello', offset: 0, length: 8, status: 'covered' }],
      }),
    ).toBe('MODIFIED')
    expect(
      resolveCryptographicIntegrity({
        issues: [CRYPTO_INTEGRITY_ISSUE.sipIdentity],
      }),
    ).toBe('MODIFIED')
    expect(resolveCryptographicIntegrity({})).toBe('UNKNOWN')
  })

  it('report separates network_checksums from cryptographic_integrity', () => {
    const plan = emptyPlan()
    const privacy = buildPrivacyReport({ plan, policy: DIAGNOSTIC_POLICY })
    const report = buildExportReport({
      plan,
      exportedFileName: 'x.pcap',
      changedPackets: 0,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [],
      checksum: {
        fields: [],
        counts: { ...emptyChecksumCounts(), recomputed: 2 },
        originalStateCounts: { ...emptyOriginalStateCounts(), VALID: 1, OFFLOADED_PARTIAL: 1 },
      },
      validation: {
        validationValid: true,
        validationIssueCount: 0,
        newBlockingIssues: [],
        preservedBaselineIssues: [],
      },
      privacy,
      diagnosticPreset: true,
      coverage: [{ protocol: 'tls-certificate', offset: 0, length: 4, status: 'redacted' }],
    })
    expect(report.validity.network_checksums).toBe('VALID')
    expect(report.validity.cryptographic_integrity).toBe('MODIFIED')
    expect(report.checksumOriginalStates?.OFFLOADED_PARTIAL).toBe(1)
    // crypto MODIFIED must not block export gate
    expect(report.exportAllowed).toBe(true)
  })
})
