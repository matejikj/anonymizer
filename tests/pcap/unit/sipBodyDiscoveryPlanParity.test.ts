/**
 * @vitest-environment node
 *
 * T02 — discovery ↔ plan parity for SIP bodies (single SDP, multipart/SIPREC, malformed).
 */

import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { readFileSync } from 'node:fs'
import { validateClassicPcap } from '../../../src/pcap/capture/validator'
import { canonicalizeIdentity } from '../../../src/mapping/canonicalize'
import type { IdentityCategory } from '../../../src/mapping/identityCategories'
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import {
  buildCombinedSipSdpPlan,
  classifySipPayload,
  parseSipMessage,
  planSipBodyOperations,
  wirePortCanonical,
  type SipMessage,
} from '../../../src/pcap/protocols/application/sip'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets'
import { runCaptureReassembly } from '../../../src/pcap/reassembly/capturePhase'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { assertCaptureHasNoPrivacyLeaks } from '../helpers/privacyLeakScan'
import {
  buildEthIpTcp,
  buildEthIpUdp,
  buildSipInviteWithSdp,
  buildSiprecInvite,
  envelope,
  SIPREC_SEED,
  SIPREC_SEED_TOKENS,
} from '../fixtures/voipCorpus'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function planIdentityKeys(
  message: SipMessage,
  buffer: Uint8Array,
  transport: 'tcp' | 'udp',
): Set<string> {
  const { operations } = buildCombinedSipSdpPlan(message, buffer)
  const keys = new Set<string>()
  for (const op of operations) {
    if (op.action !== 'map' || op.mappingCategory === null) continue
    let raw = op.canonicalText
    if (op.mappingCategory === 'port') {
      raw = wirePortCanonical(raw, transport, op.portContext)
    }
    const category = op.mappingCategory as IdentityCategory
    const canonical = canonicalizeIdentity(category, raw) ?? raw
    keys.add(`${category}:${canonical}`)
  }
  return keys
}

function discoveryIdentityKeys(
  packets: readonly PacketEnvelope[],
  policy = DIAGNOSTIC_POLICY,
): Set<string> {
  const reassembly = runCaptureReassembly(packets, policy)
  const discovery = runDiscoveryPipeline(packets, policy, 't02', 't02.pcap', {
    reassemblyContext: reassembly,
  })
  const keys = new Set<string>()
  for (const intent of discovery.intents) {
    if (intent.kind !== 'entity-replacement') continue
    keys.add(`${intent.category}:${intent.canonical}`)
  }
  return keys
}

function assertPlanSubsetOfDiscovery(
  packets: readonly PacketEnvelope[],
  sipPayload: Uint8Array,
  transport: 'tcp' | 'udp',
): void {
  const parsed = parseSipMessage(sipPayload)
  expect(parsed.kind).toBe('complete')
  if (parsed.kind !== 'complete') return
  const planKeys = planIdentityKeys(parsed.message, sipPayload, transport)
  const discKeys = discoveryIdentityKeys(packets)
  for (const key of planKeys) {
    expect(discKeys.has(key), `plan identity missing from discovery: ${key}`).toBe(true)
  }
}

describe('T02 SIP body discovery ↔ plan parity', () => {
  it('single top-level SDP (UDP)', () => {
    const payload = buildSipInviteWithSdp()
    const frame = buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload)
    assertPlanSubsetOfDiscovery([envelope(frame, 0)], payload, 'udp')
  })

  it('SIPREC multipart SDP+XML (UDP)', () => {
    const payload = buildSiprecInvite()
    const frame = buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload)
    assertPlanSubsetOfDiscovery([envelope(frame, 0)], payload, 'udp')

    const parsed = parseSipMessage(payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, payload)
    // T02 revision: SIPREC XML is structurally mapped (not whole-body silent covered).
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sip-siprec-metadata')).toBe(true)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sdp' && c.status === 'covered')).toBe(true)
    expect(
      bodyPlan.operations.some(
        (op) => op.action === 'map' && op.canonicalText.includes(SIPREC_SEED.participantAor),
      ),
    ).toBe(true)
    expect(
      bodyPlan.operations.some(
        (op) => op.action === 'map' && op.canonicalText.includes(SIPREC_SEED.sessionId),
      ),
    ).toBe(true)
  })

  it('multipart with two SDP parts', () => {
    const payload = buildSiprecInvite({ dualSdp: true })
    const frame = buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload)
    assertPlanSubsetOfDiscovery([envelope(frame, 0)], payload, 'udp')
    const parsed = parseSipMessage(payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, payload)
    expect(bodyPlan.coverage.filter((c) => c.protocol === 'sdp' && c.status === 'covered').length).toBeGreaterThanOrEqual(2)
  })

  it('multipart without SDP (only XML) still plans redaction', () => {
    const boundary = 'noxmlbound'
    const xml = `<recording aor="${SIPREC_SEED.participantAor}"/>`
    const body =
      `--${boundary}\r\n`
      + 'Content-Type: application/rs-metadata+xml\r\n\r\n'
      + xml
      + `\r\n--${boundary}--\r\n`
    const payload = latin1([
      'INVITE sip:r@h SIP/2.0',
      'Via: SIP/2.0/UDP 1.1.1.1:5060;branch=z9hG4bKnoxml',
      'From: <sip:a@h>;tag=t',
      'To: <sip:r@h>',
      'Call-ID: no-sdp-mp@h',
      `Content-Type: multipart/mixed;boundary=${boundary}`,
      `Content-Length: ${body.length}`,
      '',
      body,
    ].join('\r\n'))
    const frame = buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload)
    assertPlanSubsetOfDiscovery([envelope(frame, 0)], payload, 'udp')
    const parsed = parseSipMessage(payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, payload)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sip-siprec-metadata')).toBe(true)
    expect(
      bodyPlan.operations.some(
        (op) => op.action === 'map' && op.canonicalText.includes(SIPREC_SEED.participantAor),
      ),
    ).toBe(true)
  })

  it('invalid multipart (missing boundary) masks whole body as malformed', () => {
    const body = 'not-a-multipart-body-SECRET'
    const payload = latin1([
      'INVITE sip:r@h SIP/2.0',
      'Via: SIP/2.0/UDP 1.1.1.1:5060;branch=z9hG4bKbadmp',
      'From: <sip:a@h>;tag=t',
      'To: <sip:r@h>',
      'Call-ID: bad-mp@h',
      'Content-Type: multipart/mixed',
      `Content-Length: ${body.length}`,
      '',
      body,
    ].join('\r\n'))
    const frame = buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload)
    assertPlanSubsetOfDiscovery([envelope(frame, 0)], payload, 'udp')
    const parsed = parseSipMessage(payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, payload)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sip-multipart' && c.status === 'malformed')).toBe(true)
    expect(bodyPlan.issues.some((i) => i.startsWith('sip-multipart:'))).toBe(true)
  })

  it('nested multipart reaches inner SDP + SIPREC', () => {
    const innerBound = 'innerT02'
    const outerBound = 'outerT02'
    const sdp = [
      'v=0',
      `o=- 9007199254740993 9007199254740993 IN IP4 ${SIPREC_SEED.mediaIp}`,
      's=-',
      `c=IN IP4 ${SIPREC_SEED.mediaIp}`,
      't=0 0',
      'm=audio 49000 RTP/AVP 0',
    ].join('\r\n') + '\r\n'
    const xml =
      `<?xml version="1.0"?>\r\n`
      + `<recording xmlns="urn:ietf:params:xml:ns:recording:1">\r\n`
      + `<session session_id="${SIPREC_SEED.sessionId}">\r\n`
      + `<nameID aor="${SIPREC_SEED.participantAor}"/>\r\n`
      + `</session></recording>\r\n`
    const inner =
      `--${innerBound}\r\n`
      + 'Content-Type: application/sdp\r\n\r\n'
      + sdp
      + `\r\n--${innerBound}\r\n`
      + 'Content-Type: application/rs-metadata+xml\r\n\r\n'
      + xml
      + `\r\n--${innerBound}--\r\n`
    const body =
      `--${outerBound}\r\n`
      + `Content-Type: multipart/related;boundary=${innerBound}\r\n\r\n`
      + inner
      + `\r\n--${outerBound}--\r\n`
    const payload = latin1([
      'INVITE sip:r@h SIP/2.0',
      'Via: SIP/2.0/UDP 1.1.1.1:5060;branch=z9hG4bKnest',
      'From: <sip:a@h>;tag=t',
      'To: <sip:r@h>',
      'Call-ID: nested-mp@h',
      `Content-Type: multipart/mixed;boundary=${outerBound}`,
      `Content-Length: ${body.length}`,
      '',
      body,
    ].join('\r\n'))
    const frame = buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload)
    assertPlanSubsetOfDiscovery([envelope(frame, 0)], payload, 'udp')
    const parsed = parseSipMessage(payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, payload)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sdp' && c.status === 'covered')).toBe(true)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sip-siprec-metadata')).toBe(true)
    expect(
      bodyPlan.operations.some(
        (op) => op.action === 'map' && op.canonicalText.includes(SIPREC_SEED.participantAor),
      ),
    ).toBe(true)
  })

  it('base64 CTE part is physically masked (no silent SDP parse)', () => {
    const boundary = 'cteT02'
    const body =
      `--${boundary}\r\n`
      + 'Content-Type: application/sdp\r\n'
      + 'Content-Transfer-Encoding: base64\r\n\r\n'
      + 'di0wDQpvPS0gMSAxIElOIElQNCAxMC4wLjAuMQ0K\r\n'
      + `--${boundary}--\r\n`
    const payload = latin1([
      'INVITE sip:r@h SIP/2.0',
      'Via: SIP/2.0/UDP 1.1.1.1:5060;branch=z9hG4bKcte',
      'From: <sip:a@h>;tag=t',
      'To: <sip:r@h>',
      'Call-ID: cte-mp@h',
      `Content-Type: multipart/mixed;boundary=${boundary}`,
      `Content-Length: ${body.length}`,
      '',
      body,
    ].join('\r\n'))
    const parsed = parseSipMessage(payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, payload)
    expect(bodyPlan.issues.some((i) => i.includes('cte-base64'))).toBe(true)
    expect(bodyPlan.operations.some((op) => op.action === 'redact')).toBe(true)
    // Must not invent SDP map identities from opaque base64 bytes.
    expect(bodyPlan.operations.every((op) => op.mappingCategory !== 'sdp-session-id')).toBe(true)
  })

  it('TCP reassembly (segmented mid-body) matches discovery/plan parity', () => {
    const payload = buildSiprecInvite({ transport: 'tcp' })
    const mid = Math.floor(payload.length / 2)
    const packets = [
      envelope(buildEthIpTcp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, 1000, payload.subarray(0, mid)), 0),
      envelope(buildEthIpTcp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, 1000 + mid, payload.subarray(mid)), 1),
    ]
    // Plan keys from the complete message; discovery via reassembly overlays.
    assertPlanSubsetOfDiscovery(packets, payload, 'tcp')
    const discKeys = discoveryIdentityKeys(packets)
    expect([...discKeys].some((k) => k.startsWith('sdp-session-id:'))).toBe(true)
  })
})

describe('T02 SIPREC export pipeline', () => {
  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`exports ${level} SIPREC without leaking SDP/XML seeds`, () => {
      const payload = buildSiprecInvite()
      const frame = buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload)
      const result = runExportPipeline(
        [envelope(frame, 0)],
        level,
        `t02-siprec-${level}.pcap`,
        `t02-siprec-${level}`,
        { mappingSeed: 't02-siprec-export' },
      )
      assertCaptureHasNoPrivacyLeaks(result.built.buffer, [
        ...SIPREC_SEED_TOKENS,
        SIPREC_SEED.mediaIp,
        '9007199254740993',
      ])
      const protocols = new Set(
        result.discovery.packetDiscovery.flatMap((p) => p.coverage.map((c) => c.protocol)),
      )
      expect(protocols.has('sip-siprec-metadata')).toBe(true)
      expect(protocols.has('sdp')).toBe(true)
    })
  }
})

const OBC2_PCAP = join(import.meta.dirname ?? '.', '../../../logs/obc2.pcap')

describe('T02 obc2 SIPREC regression (local fixture)', () => {
  it.skipIf(!existsSync(OBC2_PCAP))(
    'analyzes and exports both levels without plan closure failure',
    () => {
      const fileBuf = readFileSync(OBC2_PCAP)
      const capture = readClassicPcap(
        fileBuf.buffer.slice(fileBuf.byteOffset, fileBuf.byteOffset + fileBuf.byteLength),
      )
      for (const level of ['diagnostic', 'high-privacy'] as const) {
        const result = runExportPipeline(
          capture.packets,
          level,
          `obc2-${level}.pcap`,
          `obc2-${level}`,
          { mappingSeed: `t02-obc2-${level}` },
        )
        expect(result.built.validationValid).toBe(true)
        const validation = validateClassicPcap(result.built.buffer)
        expect(validation.valid).toBe(true)
      }
    },
  )
})

describe('T02 classify path sanity', () => {
  it('UDP SIPREC classifies as complete SIP', () => {
    const payload = buildSiprecInvite()
    const frame = buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload)
    const c = classifySipPayload(frame, 42, payload.length, { portHint: true })
    expect(c.kind).toBe('complete')
  })
})
