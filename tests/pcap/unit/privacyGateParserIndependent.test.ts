/**
 * Step 6 — privacy gate hardening independent of parser success.
 *
 * The pre-existing gates (diagnosticPrivacyGate.test.ts, dtPcapRegressionGate.test.ts) seed
 * their leak scan from `discovery.analysis.entities` — a parser that fails to recognize SIP,
 * TLS, or any other structured content cannot hand an identity to that scanner, so a bug that
 * makes the parser mis-classify sensitive content as malformed/unsupported (and skip
 * structural anonymization) would sail through undetected. This file builds a fixture with a
 * unique, hardcoded canary in each sensitive category and scans the export directly for those
 * literal values — independent of what discovery concluded — plus two structural checks that
 * read only `coverage` (assertNoBlockingSpanSurvivesUnchanged) or raw bytes
 * (assertNoUnchangedWindow), never entity names.
 */

import { describe, expect, it } from 'vitest'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { createPresetProfile } from '../../../src/pcap/profile/presets'
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
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import {
  assertNoBlockingSpanSurvivesUnchanged,
  assertNoUnchangedWindow,
  tlsCertificateStructuralPreserveRanges,
  tlsHelloStructuralPreserveRanges,
} from '../helpers/privacyLeakScan'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function classicHeader() {
  return {
    format: CaptureFormat.ClassicPcap,
    endian: 1,
    timestampResolution: 0,
    versionMajor: 2,
    versionMinor: 4,
    snapLen: 65535,
    linkType: 1,
    tzOffset: 0,
    sigfigs: 0,
  } as import('../../../src/pcap/domain/types').ClassicPcapHeader
}

function envelope(data: Uint8Array, index: number): PacketEnvelope {
  return {
    packetNumber: index,
    timestamp: { ticks: 0n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24,
    data,
  }
}

function buildEthIpUdp(src: number[], dst: number[], srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  const total = 14 + 20 + 8 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + 8 + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 17
  buf.set(src, 26)
  buf.set(dst, 30)
  const udpStart = 34
  buf[udpStart] = (srcPort >> 8) & 0xff
  buf[udpStart + 1] = srcPort & 0xff
  buf[udpStart + 2] = (dstPort >> 8) & 0xff
  buf[udpStart + 3] = dstPort & 0xff
  const udpTotalLen = 8 + payload.length
  buf[udpStart + 4] = (udpTotalLen >> 8) & 0xff
  buf[udpStart + 5] = udpTotalLen & 0xff
  buf.set(payload, udpStart + 8)
  return buf
}

function buildEthIpTcp(src: number[], dst: number[], srcPort: number, dstPort: number, payload: Uint8Array): Uint8Array {
  const total = 14 + 20 + 20 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + 20 + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 6
  buf.set(src, 26)
  buf.set(dst, 30)
  const tcpStart = 34
  buf[tcpStart] = (srcPort >> 8) & 0xff
  buf[tcpStart + 1] = srcPort & 0xff
  buf[tcpStart + 2] = (dstPort >> 8) & 0xff
  buf[tcpStart + 3] = dstPort & 0xff
  buf[tcpStart + 12] = 0x50
  buf.set(payload, tcpStart + 20)
  return buf
}

// --- Canary 1: malformed SIP (invalid header-name character) ---
const MALFORMED_SIP_CANARY = 'MALFORMED-SIP-CANARY-9f3a1c'
function buildMalformedSip(): Uint8Array {
  // A control byte (0x01) in the header name is not a token char -> header-name-char -> the
  // whole message is malformed, per header.ts's parseHeaderLine.
  const text = [
    'INVITE sip:a@b.c SIP/2.0\r\n',
    `X-\x01Bad: ${MALFORMED_SIP_CANARY}\r\n`,
    'Content-Length: 0\r\n',
    '\r\n',
  ].join('')
  return buildEthIpUdp([192, 168, 50, 1], [192, 168, 50, 2], 5060, 5060, latin1(text))
}

// --- Canary 2: TLS Certificate SAN IP + subject, arriving as the second handshake message
// in one record (the step-3 scenario) ---
const TLS_SAN_IP = [172, 31, 200, 44]
const TLS_SUBJECT_CANARY = 'CN=TlsSubjectCanary7788'
function buildServerHelloMessage(): number[] {
  const body = [0x03, 0x03, ...new Array(32).fill(0x22), 0x00, 0xc0, 0x2f, 0x00]
  return [0x02, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body]
}
function buildTlsCertificateRecord(): Uint8Array {
  const sanDer = [0x87, 0x04, ...TLS_SAN_IP]
  const subjectBytes = Array.from(TLS_SUBJECT_CANARY, (c) => c.charCodeAt(0))
  const certBody = [...sanDer, ...subjectBytes]
  const certList = [(certBody.length >> 16) & 0xff, (certBody.length >> 8) & 0xff, certBody.length & 0xff, ...certBody]
  const certHandshakeBody = [(certList.length >> 16) & 0xff, (certList.length >> 8) & 0xff, certList.length & 0xff, ...certList]
  const certMessage = [0x0b, (certHandshakeBody.length >> 16) & 0xff, (certHandshakeBody.length >> 8) & 0xff, certHandshakeBody.length & 0xff, ...certHandshakeBody]
  const messages = [...buildServerHelloMessage(), ...certMessage]
  const record = new Uint8Array([0x16, 0x03, 0x03, (messages.length >> 8) & 0xff, messages.length & 0xff, ...messages])
  return buildEthIpTcp([10, 0, 0, 2], [93, 184, 216, 34], 443, 55123, record)
}

// --- Canary 3: unsupported/unknown text payload on a non-standard port ---
const UNKNOWN_TEXT_CANARY = 'UNKNOWN-TEXT-PAYLOAD-CANARY-42ab'
const UNKNOWN_TEXT_IP = [198, 51, 100, 77] // embedded as ASCII dotted text
function buildUnknownTextPayload(): Uint8Array {
  const text = `${UNKNOWN_TEXT_CANARY} contact=${UNKNOWN_TEXT_IP.join('.')} end`
  return buildEthIpUdp([192, 168, 60, 1], [192, 168, 60, 2], 47000, 47001, latin1(text))
}

// --- Canary 4: raw binary IP embedded in an otherwise-opaque payload (not a recognized
// protocol field at all) ---
const BINARY_IP_CANARY = [203, 0, 113, 55]
function buildBinaryIpPayload(): Uint8Array {
  const payload = new Uint8Array([0xde, 0xad, ...BINARY_IP_CANARY, 0xbe, 0xef])
  return buildEthIpUdp([192, 168, 70, 1], [192, 168, 70, 2], 48000, 48001, payload)
}

function buildExport(packets: PacketEnvelope[], level: 'diagnostic' | 'high-privacy', generationId: string) {
  const policy = level === 'diagnostic' ? DIAGNOSTIC_POLICY : HIGH_PRIVACY_POLICY
  const profile = createPresetProfile(level, { id: generationId, name: 'gate' })
  const reassembly = runCaptureReassembly(packets, policy)
  const discovery = runDiscoveryPipeline(packets, policy, generationId, 'fixture.pcap', { reassemblyContext: reassembly })
  const authority = new MappingAuthority({
    ip: profile.mapping.ip,
    mac: profile.mapping.mac,
    timestamps: profile.mapping.timestamps,
    ephemeralPorts: profile.mapping.ephemeralPorts,
      contentSignalingPorts: profile.mapping.contentSignalingPorts,
    vlan: profile.mapping.vlan,
  })
  const identities = identitiesFromDiscovery(discovery)
  let resolved = authority.resolve({ generationId, sourceId: 'fixture.pcap', identities })
  if (!resolved.ok) throw new Error(`mapping resolve failed: ${resolved.message}`)
  let unresolvedFailures: import('../../../src/pcap/plan/mappingClosureValidation').MappingClosureFailure[] = []
  let closure = validateMappingClosure(discovery.intents, resolved.snapshot)
  if (!closure.ok) {
    const topUp = identitiesForClosureFailures(closure.failures)
    resolved = authority.resolve({ generationId, sourceId: 'fixture.pcap', identities: dedupeIdentities([...identities, ...topUp]) })
    if (!resolved.ok) throw new Error(`mapping resolve failed: ${resolved.message}`)
    closure = validateMappingClosure(discovery.intents, resolved.snapshot)
    if (!closure.ok) unresolvedFailures = [...closure.failures]
  }
  const plan = buildDeterministicPlan({
    generationId,
    profile,
    format: CaptureFormat.ClassicPcap,
    fileName: 'fixture.pcap',
    packets,
    policy,
    snapshot: resolved.snapshot,
    reassemblyContext: reassembly,
    classicHeader: classicHeader(),
    packetDiscovery: discovery.packetDiscovery,
    sourceId: 'fixture.pcap',
    unresolvedClosureFailures: unresolvedFailures,
  })
  const built = buildCaptureFromPlan(plan, packets)
  return { discovery, plan, built }
}

const RAW_CANARIES = [MALFORMED_SIP_CANARY, TLS_SUBJECT_CANARY, UNKNOWN_TEXT_CANARY]
const RAW_IP_CANARIES = [TLS_SAN_IP, UNKNOWN_TEXT_IP, BINARY_IP_CANARY]

function scanForTextCanary(buffer: Uint8Array, canary: string): boolean {
  const text = Buffer.from(buffer).toString('latin1')
  return text.includes(canary)
}

function scanForRawIp(buffer: Uint8Array, ip: readonly number[]): boolean {
  for (let i = 0; i + 4 <= buffer.length; i++) {
    if (buffer[i] === ip[0] && buffer[i + 1] === ip[1] && buffer[i + 2] === ip[2] && buffer[i + 3] === ip[3]) return true
  }
  return false
}

describe('privacy gate independent of parser success (step 6)', () => {
  const packets = [
    envelope(buildMalformedSip(), 0),
    envelope(buildTlsCertificateRecord(), 1),
    envelope(buildUnknownTextPayload(), 2),
    envelope(buildBinaryIpPayload(), 3),
  ]

  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`finds zero canaries in the ${level} export, independent of discovered entities`, () => {
      const { discovery, plan, built } = buildExport(packets, level, `gate-${level}`)
      const outBuffer = new Uint8Array(built.buffer)

      for (const canary of RAW_CANARIES) {
        expect(scanForTextCanary(outBuffer, canary), `text canary leaked: ${canary}`).toBe(false)
      }
      for (const ip of RAW_IP_CANARIES) {
        expect(scanForRawIp(outBuffer, ip), `raw IP canary leaked: ${ip.join('.')}`).toBe(false)
      }

      // Structural check: no blocking span byte-identical to original, reading only coverage.
      const outPackets = readClassicPcap(built.buffer).packets
      for (const pd of discovery.packetDiscovery) {
        if (plan.droppedPacketNumbers.includes(packets[pd.packetIndex]!.packetNumber)) continue
        const outIdx = outPackets.findIndex((p) => p.packetNumber === packets[pd.packetIndex]!.packetNumber)
        if (outIdx < 0) continue
        assertNoBlockingSpanSurvivesUnchanged(
          packets[pd.packetIndex]!.data,
          outPackets[outIdx]!.data,
          pd.coverage,
          packets[pd.packetIndex]!.packetNumber,
        )
      }
    })

    it(`has no long unchanged byte window over the application payload under ${level}`, () => {
      const { discovery, plan, built } = buildExport(packets, level, `gate-window-${level}`)
      const outPackets = readClassicPcap(built.buffer).packets
      for (const pd of discovery.packetDiscovery) {
        const packetNumber = packets[pd.packetIndex]!.packetNumber
        if (plan.droppedPacketNumbers.includes(packetNumber)) continue
        const outIdx = outPackets.findIndex((p) => p.packetNumber === packetNumber)
        if (outIdx < 0) continue
        const original = packets[pd.packetIndex]!.data
        const anonymized = outPackets[outIdx]!.data
        // Transport/network framing spans (ports, lengths, checksums) legitimately stay
        // unchanged — e.g. well-known port 5060 is not pseudonymized. Only application-layer
        // content spans carry the identities/text this scan is meant to protect.
        const APPLICATION_LAYER_PROTOCOLS = new Set([
          'sip', 'sip-body', 'sdp', 'tls-certificate', 'tls-clienthello', 'tls-serverhello',
          'tls-handshake-unsupported', 'http', 'http-body', 'heuristic', 'payload',
          'application', 'icmp-payload', 'icmp-echo-payload',
        ])
        for (const span of pd.coverage) {
          if (span.status === 'encrypted') continue // proven ciphertext, exempt by design
          if (!APPLICATION_LAYER_PROTOCOLS.has(span.protocol)) continue
          if (span.length < 8) continue
          // T47 — TLS Hello may keep framing/version/cipher bytes; never random/session_id/unknown ext.
          const allowed =
            span.protocol === 'tls-serverhello'
              ? tlsHelloStructuralPreserveRanges(original, span, 'server')
              : span.protocol === 'tls-clienthello'
                ? tlsHelloStructuralPreserveRanges(original, span, 'client')
                : span.protocol === 'tls-certificate'
                  ? tlsCertificateStructuralPreserveRanges(original, span)
                  : []
          assertNoUnchangedWindow(
            original,
            anonymized,
            span,
            8,
            `packet ${packetNumber} span ${span.protocol}/${span.status}`,
            allowed,
          )
        }
      }
    })
  }
})
