/**
 * @vitest-environment node
 *
 * T01 — sdp-session-id identity + modular session-version shift.
 */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { canonicalizeIdentity } from '../../../src/mapping/canonicalize'
import { DEFAULT_MAPPING_CONFIG } from '../../../src/pcap/anonymization/mapping'
import { createTestSessionMapping } from '../../../src/pcap/anonymization/testModeSeed'
import { validateClassicPcap } from '../../../src/pcap/capture/validator'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { runDiscoveryPipeline } from '../../../src/pcap/discovery/discoveryPipeline'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { DIAGNOSTIC_POLICY } from '../../../src/pcap/profile/presets'
import {
  extractSdpEntities,
  parseSdp,
  shiftSessionVersion,
  independentVersionDelta,
} from '../../../src/pcap/protocols/application/sdp'
import {
  buildCombinedSipSdpPlan,
  classifySipPayload,
  parseSipMessage,
} from '../../../src/pcap/protocols/application/sip'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { sanitizeSipMessage } from '../../../src/pcap/sanitize/sip'
import { RECOVERY_CATEGORY_IDS } from '../../../src/pcap/recovery/codec/categoryIds'
import { runExportPipeline } from '../helpers/diagnosticPipeline'
import { buildEthIpUdp, envelope } from '../fixtures/voipCorpus'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function sdpBody(lines: string[]): string {
  return `${lines.join('\r\n')}\r\n`
}

function buildSipWithOrigin(sessionId: string, sessionVersion: string, ip = '10.0.0.1'): Uint8Array {
  const sdp = sdpBody([
    'v=0',
    `o=- ${sessionId} ${sessionVersion} IN IP4 ${ip}`,
    's=-',
    `c=IN IP4 ${ip}`,
    't=0 0',
    'm=audio 4000 RTP/AVP 0',
  ])
  const headers = [
    `INVITE sip:bob@${ip} SIP/2.0`,
    `Via: SIP/2.0/UDP ${ip}:5060;branch=z9hG4bK776asdhds`,
    `From: <sip:alice@${ip}>;tag=from-tag-1`,
    `Call-ID: dialog-t01@${ip}`,
    'Content-Type: application/sdp',
    `Content-Length: ${sdp.length}`,
  ]
  return latin1(`${headers.join('\r\n')}\r\n\r\n${sdp}`)
}

function applySanitized(frame: Uint8Array, seed: string): string {
  const udpOffset = 42
  const payloadLen = frame.length - udpOffset
  const classified = classifySipPayload(frame, udpOffset, payloadLen, { portHint: true })
  expect(classified.kind).toBe('complete')
  if (classified.kind !== 'complete') throw new Error('sip classify failed')
  const collector = new PatchCollector(frame.length)
  const mapping = createTestSessionMapping(seed, {
    ...DEFAULT_MAPPING_CONFIG,
    ephemeralPorts: 'permute',
  })
  sanitizeSipMessage(frame, classified.message, 'udp', collector, mapping, 0)
  collector.resolveDeferred({ mapping })
  const out = new Uint8Array(frame)
  for (const patch of collector.getPatches()) out.set(patch.data, patch.offset)
  return new TextDecoder('latin1').decode(out.slice(udpOffset))
}

describe('T01 / T-01.B session-version journal op', () => {
  it('registers session-version-shift symbolic op without legacyResolve', () => {
    const payload = buildSipWithOrigin('2890844526', '2890844527')
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, payload)
    const udpOffset = 42
    const classified = classifySipPayload(frame, udpOffset, frame.length - udpOffset, {
      portHint: true,
    })
    expect(classified.kind).toBe('complete')
    if (classified.kind !== 'complete') throw new Error('sip classify failed')
    const collector = new PatchCollector(frame.length)
    const mapping = createTestSessionMapping('t01-sv-journal')
    sanitizeSipMessage(frame, classified.message, 'udp', collector, mapping, 0)
    const ops = collector.getSymbolicJournalOps()
    const sv = ops.filter((o) => o.kind === 'session-version-shift')
    expect(sv.length).toBeGreaterThanOrEqual(1)
    expect(sv[0]!.kind).toBe('session-version-shift')
    if (sv[0]!.kind !== 'session-version-shift') throw new Error('expected session-version-shift')
    expect(sv[0].versionDigits).toBe('2890844527')
    expect(sv[0].sessionIdCanonical.endsWith('2890844526')).toBe(true)
    expect(collector.isDeferredFullySymbolized()).toBe(true)
    collector.resolveDeferred({ mapping })
    const out = new Uint8Array(frame)
    for (const patch of collector.getPatches()) out.set(patch.data, patch.offset)
    const text = new TextDecoder('latin1').decode(out.slice(udpOffset))
    expect(text).not.toContain('2890844526')
    expect(text).not.toContain('o=- 2890844526 2890844527')
  })
})

describe('T01 sdp-session-id mapping', () => {
  it('canonicalizes 1–64 digit strings without Number precision loss', () => {
    expect(canonicalizeIdentity('sdp-session-id', '0')).toBe('0')
    expect(canonicalizeIdentity('sdp-session-id', '1')).toBe('1')
    const nineteen = '1234567890123456789'
    expect(canonicalizeIdentity('sdp-session-id', nineteen)).toBe(nineteen)
    const twenty = '9007199254740993001' // > 2^53
    expect(canonicalizeIdentity('sdp-session-id', twenty)).toBe(twenty)
    expect(canonicalizeIdentity('sdp-session-id', '1'.repeat(64))).toBe('1'.repeat(64))
    expect(canonicalizeIdentity('sdp-session-id', '1'.repeat(65))).toBeNull()
    expect(canonicalizeIdentity('sdp-session-id', '12a')).toBeNull()
  })

  it('aliases same length, digits only, ≠ original, bijection, leading-zero rule', () => {
    const mapping = createTestSessionMapping('t01-session-id')
    const a = mapping.map('sdp-session-id', '2890844526')
    const b = mapping.map('sdp-session-id', '2890844526')
    expect(a).toBe(b)
    expect(a).toHaveLength(10)
    expect(a).toMatch(/^\d+$/)
    expect(a).not.toBe('2890844526')
    expect(a.startsWith('0')).toBe(false)

    const zeroPad = mapping.map('sdp-session-id', '012345')
    expect(zeroPad).toHaveLength(6)
    expect(zeroPad.startsWith('0')).toBe(true)
    expect(zeroPad).not.toBe('012345')

    const other = mapping.map('sdp-session-id', '2890844527')
    expect(other).not.toBe(a)
    expect(mapping.get('sdp-session-id', '2890844526')).toBe(a)
  })

  it('extracts session-id as sdp-session-id and session-version without identity category', () => {
    const buf = latin1(sdpBody([
      'v=0',
      'o=jnovak 2890844526 2890844527 IN IP4 192.168.1.10',
      's=-',
      'c=IN IP4 192.168.1.10',
      't=0 0',
      'm=audio 49170 RTP/AVP 0',
    ]))
    const parsed = parseSdp(buf)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return
    const { entities } = extractSdpEntities(parsed.session, buf)
    const sid = entities.find((e) => e.kind === 'session-id')
    const ver = entities.find((e) => e.kind === 'session-version')
    expect(sid?.mappingCategory).toBe('sdp-session-id')
    expect(ver?.mappingCategory).toBeNull()
    expect(sid?.canonicalText).toBe('jnovak\u001f2890844526')
    expect(ver?.sessionIdForVersion).toBe('jnovak\u001f2890844526')
  })

  it('two authors with the same numeric session-id get distinct aliases', () => {
    const mapping = createTestSessionMapping('t01-two-authors')
    const id = '2890844526'
    const a = mapping.map('sdp-session-id', `alice\u001f${id}`)
    const b = mapping.map('sdp-session-id', `bob\u001f${id}`)
    expect(a).toHaveLength(id.length)
    expect(b).toHaveLength(id.length)
    expect(a).toMatch(/^\d+$/)
    expect(b).toMatch(/^\d+$/)
    expect(a).not.toBe(id)
    expect(b).not.toBe(id)
    expect(a).not.toBe(b)
  })

  it('recovery category id for sdp-session-id is stable append-only 16', () => {
    expect(RECOVERY_CATEGORY_IDS['sdp-session-id']).toBe(16)
    expect(RECOVERY_CATEGORY_IDS.other).toBe(15)
  })
})

describe('T01 session-version modular shift', () => {
  it('preserves +1 increments when version width matches session-id width', () => {
    const id = '1000'
    const alias = '2000'
    expect(shiftSessionVersion('1000', id, alias)).toBe('2000')
    expect(shiftSessionVersion('1001', id, alias)).toBe('2001')
    expect(shiftSessionVersion('1002', id, alias)).toBe('2002')
  })

  it('when version equals session-id, shifted version equals alias', () => {
    const id = '2890844526'
    const alias = '3141592653'
    expect(shiftSessionVersion(id, id, alias)).toBe(alias)
  })

  it('short version uses independent non-zero delta not derivable from id alone', () => {
    const d1 = independentVersionDelta('1111', 1)
    const d2 = independentVersionDelta('2222', 1)
    expect(d1).not.toBe(0n)
    expect(d2).not.toBe(0n)
    expect(d1).not.toBe(d2)
    const v1 = shiftSessionVersion('1', '1111', '9999')
    const v2 = shiftSessionVersion('1', '2222', '8888')
    expect(v1).toHaveLength(1)
    expect(v2).toHaveLength(1)
    expect(v1).not.toBe('1')
    expect(v2).not.toBe('1')
    // Different sessions with version "1" must not share the same alias.
    expect(v1).not.toBe(v2)
  })

  it('same version + same session-id alias → same shifted version', () => {
    const a = shiftSessionVersion('42', '999', '111')
    const b = shiftSessionVersion('42', '999', '111')
    expect(a).toBe(b)
    expect(a).toHaveLength(2)
  })

  it('re-offer through sanitize keeps +1 readable and never leaks originals', () => {
    const seed = 't01-reoffer'
    const id = '5000'
    const frames = [1, 2, 3].map((ver) => {
      const payload = buildSipWithOrigin(id, String(ver))
      const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, payload)
      return applySanitized(frame, seed)
    })
    const versions = frames.map((text) => {
      const m = text.match(/\r\no=-\s+\d+\s+(\d+)\s+IN IP4/i)
      expect(m).not.toBeNull()
      return Number(m![1])
    })
    expect(versions[1]! - versions[0]!).toBe(1)
    expect(versions[2]! - versions[1]!).toBe(1)
    for (const text of frames) {
      expect(text).not.toContain(id)
      expect(text).not.toMatch(/\r\no=-\s+5000\s/)
    }
  })
})

describe('T01 discovery ↔ plan parity for SDP session-id', () => {
  it('every sdp-session-id requested by plan ops is present in discovery intents', () => {
    const payload = buildSipWithOrigin('1234567890123456789', '1234567890123456789')
    const data = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, payload)
    const packets: PacketEnvelope[] = [envelope(data, 0)]
    const policy = DIAGNOSTIC_POLICY
    const discovery = runDiscoveryPipeline(packets, policy, 't01', 't01.pcap')
    const sessionIdIntents = discovery.intents.filter(
      (i) => i.kind === 'entity-replacement' && i.category === 'sdp-session-id',
    )
    expect(sessionIdIntents.length).toBeGreaterThan(0)

    const sip = parseSipMessage(payload)
    expect(sip.kind).toBe('complete')
    if (sip.kind !== 'complete') return
    const { operations } = buildCombinedSipSdpPlan(sip.message, payload)
    const planSessionIds = operations.filter((op) => op.mappingCategory === 'sdp-session-id')
    expect(planSessionIds.length).toBeGreaterThan(0)
    for (const op of planSessionIds) {
      const found = sessionIdIntents.some(
        (i) => i.kind === 'entity-replacement' && i.canonical === op.canonicalText,
      )
      expect(found).toBe(true)
    }
    // session-version must not be registered as an identity
    expect(
      discovery.intents.some(
        (i) => i.kind === 'entity-replacement' && i.canonical === '1234567890123456789'
          && i.category !== 'sdp-session-id' && i.category !== 'ipv4' && i.category !== 'hostname'
          && i.category !== 'sip-user' && i.category !== 'sip-call-id' && i.category !== 'sip-token',
      ),
    ).toBe(false)
  })
})

describe('T01 export pipeline with 19-digit session-id', () => {
  for (const level of ['diagnostic', 'high-privacy'] as const) {
    it(`exports ${level} without leaking 19-digit session-id`, () => {
      const sessionId = '1234567890123456789'
      const payload = buildSipWithOrigin(sessionId, sessionId)
      const data = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, payload)
      const result = runExportPipeline(
        [envelope(data, 0)],
        level,
        `t01-${level}.pcap`,
        `t01-${level}`,
        { mappingSeed: 't01-export' },
      )
      const outText = new TextDecoder('latin1').decode(new Uint8Array(result.built.buffer))
      expect(outText).not.toContain(sessionId)
      expect(result.built.buffer.byteLength).toBeGreaterThan(24)
    })
  }
})

const HI2_PCAP = join(import.meta.dirname ?? '.', '../../../logs/hi2-20261012-001-sip.pcap')

describe('T01 hi2 SIP regression (local fixture)', () => {
  it.skipIf(!existsSync(HI2_PCAP))(
    'analyzes and exports both levels without leaking original session-ids',
    () => {
      const fileBuf = readFileSync(HI2_PCAP)
      const bytes = new Uint8Array(fileBuf)
      const capture = readClassicPcap(fileBuf.buffer.slice(fileBuf.byteOffset, fileBuf.byteOffset + fileBuf.byteLength))
      const packets = capture.packets

      // Collect original o= session-id tokens from the raw capture (digits only).
      const rawText = new TextDecoder('latin1').decode(bytes)
      const originalIds = new Set<string>()
      for (const m of rawText.matchAll(/\r\no=\S+\s+(\d{10,})\s+\d+/g)) {
        originalIds.add(m[1]!)
      }
      expect(originalIds.size).toBeGreaterThan(0)

      for (const level of ['diagnostic', 'high-privacy'] as const) {
        const result = runExportPipeline(
          packets,
          level,
          `hi2-${level}.pcap`,
          `hi2-${level}`,
          { mappingSeed: `t01-hi2-${level}` },
        )
        const out = new Uint8Array(result.built.buffer)
        const outText = new TextDecoder('latin1').decode(out)
        for (const id of originalIds) {
          expect(outText).not.toContain(id)
        }
        const validation = validateClassicPcap(result.built.buffer)
        expect(validation.valid).toBe(true)
      }
    },
  )
})
