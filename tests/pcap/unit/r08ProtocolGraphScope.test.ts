/**
 * R08 — AMI EventList, Q.931 multi-link, and SMPP session graphs scoped in production sanitize.
 */
import { describe, expect, it, beforeEach } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp } from '../fixtures/voipCorpus'
import { LINKTYPE_LINUX_LAPD } from '../../../src/pcap/sanitize/isdn/lapd'
import { smppTransportSessionForMapping } from '../../../src/pcap/sanitize/smpp/smppSessionGraph'
import {
  disposeProtocolGraphStateForSession,
  resetProtocolGraphStateRegistryForTests,
} from '../../../src/pcap/sanitize/protocolGraphState'

function packetInput(data: Uint8Array, linkType = 1) {
  return { index: 0, data, capturedLength: data.length, originalLength: data.length, linkType }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function writeU32(buf: Uint8Array, o: number, v: number): void {
  buf[o] = (v >>> 24) & 0xff
  buf[o + 1] = (v >>> 16) & 0xff
  buf[o + 2] = (v >>> 8) & 0xff
  buf[o + 3] = v & 0xff
}

function cOctet(s: string): Uint8Array {
  const out = new Uint8Array(s.length + 1)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  out[s.length] = 0
  return out
}

function wrapSmppPdu(commandId: number, status: number, seq: number, body: Uint8Array): Uint8Array {
  const len = 16 + body.length
  const out = new Uint8Array(len)
  writeU32(out, 0, len)
  writeU32(out, 4, commandId)
  writeU32(out, 8, status)
  writeU32(out, 12, seq)
  out.set(body, 16)
  return out
}

/** Minimal Q.931 Setup with ASCII called-party number. */
function q931SetupWithCalled(digits: string, callRef = 0x07): Uint8Array {
  const digitBytes = new TextEncoder().encode(digits)
  const calledIe = new Uint8Array(2 + 2 + digitBytes.length)
  calledIe[0] = 0x70
  calledIe[1] = 2 + digitBytes.length
  calledIe[2] = 0x80
  calledIe[3] = 0x90
  calledIe.set(digitBytes, 4)
  const out = new Uint8Array(2 + 1 + 1 + calledIe.length)
  out[0] = 0x08
  out[1] = 0x01
  out[2] = callRef
  out[3] = 0x05
  out.set(calledIe, 4)
  return out
}

function lapdIframe(tei: number, q931: Uint8Array): Uint8Array {
  const addr1 = 0x00
  const addr2 = ((tei & 0x7f) << 1) | 0x01
  const out = new Uint8Array(2 + 2 + q931.length)
  out[0] = addr1
  out[1] = addr2
  out[2] = 0x00
  out[3] = 0x00
  out.set(q931, 4)
  return out
}

function linuxCookedLapd(lapd: Uint8Array): Uint8Array {
  const out = new Uint8Array(16 + lapd.length)
  out.set(lapd, 16)
  return out
}

describe('R08 AMI EventList transport scope', () => {
  beforeEach(() => resetProtocolGraphStateRegistryForTests())

  it('does not count child events from a different TCP AMI session', () => {
    const mapping = new SessionMapping(undefined, { seed: 'r08-ami-el' })
    const startA = [
      'Action: Status',
      'ActionID: shared-act',
      'EventList: start',
      'ListItems: 1',
      '',
    ].join('\r\n')
    const pktA = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 5038, 1, new TextEncoder().encode(startA))
    const rA = sanitizePacket(packetInput(pktA), DIAGNOSTIC_POLICY, mapping)
    expect(rA.issues?.some((i) => i.includes('eventlist-items'))).toBe(true)

    const strayB = [
      'Event: StatusComplete',
      'ActionID: shared-act',
      'Privilege: system,all',
      '',
    ].join('\r\n')
    const pktB = buildEthIpTcp([10, 0, 1, 1], [10, 0, 1, 2], 40_001, 5038, 2, new TextEncoder().encode(strayB))
    const rB = sanitizePacket({ ...packetInput(pktB), index: 1 }, DIAGNOSTIC_POLICY, mapping)
    expect(rB.issues?.some((i) => i.includes('eventlist-child'))).toBe(false)

    const childA = [
      'Event: StatusComplete',
      'ActionID: shared-act',
      'Privilege: system,all',
      '',
    ].join('\r\n')
    const pktA2 = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40_000, 5038, 3, new TextEncoder().encode(childA))
    const rA2 = sanitizePacket({ ...packetInput(pktA2), index: 2 }, DIAGNOSTIC_POLICY, mapping)
    expect(rA2.issues?.some((i) => i.includes('eventlist-child') || i.includes('eventlist-complete'))).toBe(
      true,
    )
  })
})

describe('R08 Q.931 link scope', () => {
  beforeEach(() => resetProtocolGraphStateRegistryForTests())

  it('maps the same called party on two TEIs to distinct aliases', () => {
    const mapping = new SessionMapping(undefined, { seed: 'r08-q931-link' })
    const digits = '420777888999'
    const frame1 = linuxCookedLapd(lapdIframe(1, q931SetupWithCalled(digits)))
    const frame2 = linuxCookedLapd(lapdIframe(2, q931SetupWithCalled(digits)))
    const r1 = sanitizePacket({ ...packetInput(frame1), linkType: LINKTYPE_LINUX_LAPD, index: 0 }, DIAGNOSTIC_POLICY, mapping)
    const r2 = sanitizePacket({ ...packetInput(frame2), linkType: LINKTYPE_LINUX_LAPD, index: 1 }, DIAGNOSTIC_POLICY, mapping)
    const out1 = applyPatches(frame1, r1)
    const out2 = applyPatches(frame2, r2)
    const latin1 = new TextDecoder('latin1')
    expect(latin1.decode(out1).includes(digits)).toBe(false)
    expect(latin1.decode(out2).includes(digits)).toBe(false)
    expect(latin1.decode(out1)).not.toBe(latin1.decode(out2))
  })

  it('flags multi-link graph when the same CR appears on two LAPD TEIs', () => {
    const mapping = new SessionMapping(undefined, { seed: 'r08-q931-multilink' })
    const digits = '420111222333'
    const frame1 = linuxCookedLapd(lapdIframe(1, q931SetupWithCalled(digits, 0x07)))
    const frame2 = linuxCookedLapd(lapdIframe(2, q931SetupWithCalled(digits, 0x07)))
    const r1 = sanitizePacket(
      { ...packetInput(frame1), linkType: LINKTYPE_LINUX_LAPD, index: 0 },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    const r2 = sanitizePacket(
      { ...packetInput(frame2), linkType: LINKTYPE_LINUX_LAPD, index: 1 },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    expect(r1.issues?.includes('q931-multi-link-graph')).toBe(false)
    expect(r2.issues).toContain('q931-multi-link-graph')
  })
})

describe('R08 SMPP account + transport scope', () => {
  beforeEach(() => resetProtocolGraphStateRegistryForTests())

  it('does not correlate submit_sm_resp across two TCP sessions with the same message_id', () => {
    const mapping = new SessionMapping(undefined, { seed: 'r08-smpp-scope' })
    const mid = 'shared-smsc-mid-001'
    const bindA = wrapSmppPdu(
      0x00000002,
      0,
      1,
      new Uint8Array([...cOctet('accountA'), ...cOctet('secret'), ...cOctet(''), 0x34, 0x00, 0x00, ...cOctet('')]),
    )
    const bindB = wrapSmppPdu(
      0x00000002,
      0,
      1,
      new Uint8Array([...cOctet('accountB'), ...cOctet('secret'), ...cOctet(''), 0x34, 0x00, 0x00, ...cOctet('')]),
    )
    const respA = wrapSmppPdu(0x80000004, 0, 2, cOctet(mid))
    const respB = wrapSmppPdu(0x80000004, 0, 2, cOctet(mid))

    sanitizePacket(
      packetInput(buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 2775, 1, bindA)),
      DIAGNOSTIC_POLICY,
      mapping,
    )
    sanitizePacket(
      packetInput(buildEthIpTcp([192, 0, 2, 3], [192, 0, 2, 4], 40_001, 2775, 2, bindB)),
      DIAGNOSTIC_POLICY,
      mapping,
    )
    const rA = sanitizePacket(
      { ...packetInput(buildEthIpTcp([192, 0, 2, 2], [192, 0, 2, 1], 2775, 40_000, 3, respA)), index: 2 },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    const rB = sanitizePacket(
      { ...packetInput(buildEthIpTcp([192, 0, 2, 4], [192, 0, 2, 3], 2775, 40_001, 4, respB)), index: 3 },
      DIAGNOSTIC_POLICY,
      mapping,
    )
    const outA = applyPatches(buildEthIpTcp([192, 0, 2, 2], [192, 0, 2, 1], 2775, 40_000, 3, respA), rA)
    const outB = applyPatches(buildEthIpTcp([192, 0, 2, 4], [192, 0, 2, 3], 2775, 40_001, 4, respB), rB)
    const aMid = new TextDecoder('latin1').decode(outA.slice(-mid.length - 1, -1))
    const bMid = new TextDecoder('latin1').decode(outB.slice(-mid.length - 1, -1))
    expect(aMid).not.toBe(bMid)
  })

  it('clears mapping-scoped SMPP graphs on session dispose', () => {
    const mapping = new SessionMapping(undefined, { seed: 'r08-smpp-dispose' })
    const session = smppTransportSessionForMapping(mapping, 'tcp:test')
    session.accountScope = 'acct'
    session.graph.noteSubmit('acct', 'mid-1', 1)
    disposeProtocolGraphStateForSession()
    const after = smppTransportSessionForMapping(mapping, 'tcp:test')
    expect(after.graph.getFacts()).toHaveLength(0)
    expect(after.graph.noteDeliver('acct', 'mid-1', 9)).toBeNull()
  })
})
