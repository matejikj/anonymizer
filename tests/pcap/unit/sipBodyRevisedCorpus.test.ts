/**
 * @vitest-environment node
 *
 * T02.R6 — full revised SIP body corpus: discovery↔plan parity + export no-leak.
 */

import { describe, expect, it } from 'vitest'
import { canonicalizeIdentity } from '../../../src/mapping/canonicalize'
import type { IdentityCategory } from '../../../src/mapping/identityCategories'
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import {
  buildCombinedSipSdpPlan,
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
  REVISED_BODY_LEAK_TOKENS,
  sipBodyRevisedCases,
} from '../fixtures/sipBodyRevisedCorpus'

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

function discoveryIdentityKeys(packets: readonly PacketEnvelope[]): Set<string> {
  const reassembly = runCaptureReassembly(packets, DIAGNOSTIC_POLICY)
  const discovery = runDiscoveryPipeline(packets, DIAGNOSTIC_POLICY, 't02-r6', 't02-r6.pcap', {
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
    expect(discKeys.has(key), `[${transport}] plan identity missing from discovery: ${key}`).toBe(true)
  }
}

describe('T02.R6 revised SIP body corpus — discovery ↔ plan parity', () => {
  for (const scenario of sipBodyRevisedCases()) {
    it(`${scenario.id} (${scenario.transport})`, () => {
      assertPlanSubsetOfDiscovery(scenario.packets, scenario.payload, scenario.transport)
    })
  }

  it('delimiter-in-data keeps two parts (decoy boundary line in text/plain)', () => {
    const scenario = sipBodyRevisedCases().find((c) => c.id === 'delimiter-in-data')!
    const parsed = parseSipMessage(scenario.payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, scenario.payload)
    expect(bodyPlan.coverage.filter((c) => c.protocol === 'sdp' && c.status === 'covered').length).toBe(1)
    expect(bodyPlan.operations.some((op) => op.action === 'map' && op.mappingCategory === 'ipv4')).toBe(true)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sip-body' && c.status === 'redacted')).toBe(true)
  })

  it('quoted-printable CTE masks part and flags cte-quoted-printable', () => {
    const scenario = sipBodyRevisedCases().find((c) => c.id === 'qp-cte-part')!
    const parsed = parseSipMessage(scenario.payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, scenario.payload)
    expect(bodyPlan.issues.some((i) => i.includes('cte-quoted-printable'))).toBe(true)
    expect(bodyPlan.operations.some((op) => op.action === 'redact')).toBe(true)
    expect(bodyPlan.operations.every((op) => op.mappingCategory !== 'sdp-session-id')).toBe(true)
  })

  it('malformed SDP sibling leaves valid part covered and marks malformed sdp', () => {
    const scenario = sipBodyRevisedCases().find((c) => c.id === 'malformed-sdp-sibling')!
    const parsed = parseSipMessage(scenario.payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, scenario.payload)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sdp' && c.status === 'covered')).toBe(true)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sdp' && c.status === 'malformed')).toBe(true)
    expect(bodyPlan.issues.some((i) => i.includes('sdp-part-malformed'))).toBe(true)
  })

  it('multipart/related exposes SIPREC + SDP coverage', () => {
    const scenario = sipBodyRevisedCases().find((c) => c.id === 'multipart-related')!
    const parsed = parseSipMessage(scenario.payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const bodyPlan = planSipBodyOperations(parsed.message, scenario.payload)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sip-siprec-metadata')).toBe(true)
    expect(bodyPlan.coverage.some((c) => c.protocol === 'sdp' && c.status === 'covered')).toBe(true)
  })
})

describe('T02.R6 revised SIP body corpus — export no-leak', () => {
  for (const scenario of sipBodyRevisedCases()) {
    it(`diagnostic export ${scenario.id}`, () => {
      const result = runExportPipeline(
        scenario.packets,
        'diagnostic',
        `t02-r6-${scenario.id}.pcap`,
        `t02-r6-${scenario.id}`,
        { mappingSeed: `t02-r6-${scenario.id}` },
      )
      // fakeDelimiterLine is intentional decoy content (framing test), not a privacy seed.
      assertCaptureHasNoPrivacyLeaks(result.built.buffer, [...REVISED_BODY_LEAK_TOKENS])
      expect(result.built.validationValid).toBe(true)
    })
  }
})
