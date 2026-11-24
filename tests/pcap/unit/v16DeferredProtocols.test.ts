/**
 * V16 — deferred protocol scope acceptance (T28/T37/T50/T51/T52 subsets).
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp, buildEthIpUdp } from '../fixtures/voipCorpus'
import { planSipBodyOperations } from '../../../src/pcap/protocols/application/sip/bodyOperations'
import { parseSipMessages } from '../../../src/pcap/protocols/application/sip/parser'
import { smppTransportSessionForMapping } from '../../../src/pcap/sanitize/smpp/smppSessionGraph'
import { AmiEventListTracker } from '../../../src/pcap/sanitize/asterisk/amiEventList'
import { resetProtocolGraphStateRegistryForTests } from '../../../src/pcap/sanitize/protocolGraphState'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'

function packetInput(data: Uint8Array) {
  return { index: 0, data, capturedLength: data.length, originalLength: data.length, linkType: 1 }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function buildIsupIamBody(calledDigits: string): Uint8Array {
  const tbcd = encodeTbcd(calledDigits, Math.ceil(calledDigits.length / 2), TBCD_GSM)!
  const calledContents = new Uint8Array(2 + tbcd.length)
  calledContents[0] = 0x83
  calledContents[1] = 0x10
  calledContents.set(tbcd, 2)
  const isup = new Uint8Array(2 + 1 + 5 + 2 + 1 + calledContents.length)
  isup[0] = 0x34
  isup[1] = 0x12
  isup[2] = 0x01
  isup[8] = 2
  isup[9] = 0
  isup[10] = calledContents.length
  isup.set(calledContents, 11)
  return isup
}

function buildIsupAnmBody(callingDigits: string): Uint8Array {
  const tbcd = encodeTbcd(callingDigits, Math.ceil(callingDigits.length / 2), TBCD_GSM)!
  const callingContents = new Uint8Array(2 + tbcd.length)
  callingContents[0] = 0x83
  callingContents[1] = 0x10
  callingContents.set(tbcd, 2)
  const isup = new Uint8Array(2 + 1 + 1 + 2 + callingContents.length)
  isup[0] = 0x34
  isup[1] = 0x12
  isup[2] = 0x09
  isup[3] = 1
  isup[4] = 0x0a
  isup[5] = callingContents.length
  isup.set(callingContents, 6)
  return isup
}

describe('V16 SIP-I ISUP child (T37/T25)', () => {
  it('maps called party in application/isup body instead of blanket mask', () => {
    const digits = '420777888999'
    const isup = buildIsupIamBody(digits)
    const headers = [
      'INVITE sip:trunk@example.com SIP/2.0',
      'Via: SIP/2.0/UDP 10.0.0.1:5060',
      'From: <sip:a@example.com>;tag=1',
      'To: <sip:b@example.com>',
      'Call-ID: sip-i-001',
      'CSeq: 1 INVITE',
      'Content-Type: application/isup',
      `Content-Length: ${isup.length}`,
    ]
    const buf = new TextEncoder().encode(`${headers.join('\r\n')}\r\n\r\n`)
    const full = new Uint8Array(buf.length + isup.length)
    full.set(buf, 0)
    full.set(isup, buf.length)
    const stream = parseSipMessages(full)
    const plan = planSipBodyOperations(stream.messages[0]!.message, full)
    expect(plan.coverage.some((c) => c.protocol === 'sip-isup-number')).toBe(true)
    expect(plan.issues.some((i) => i.includes('pending-t25'))).toBe(false)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, full)
    const mapping = new SessionMapping(undefined, { seed: 'v16-sipi' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('777888999')).toBe(false)
  })

  it('maps calling party in ISUP ANM via shared T25 walk', () => {
    const digits = '420111222333'
    const isup = buildIsupAnmBody(digits)
    const headers = [
      'NOTIFY sip:trunk@example.com SIP/2.0',
      'Via: SIP/2.0/UDP 10.0.0.1:5060',
      'From: <sip:a@example.com>;tag=1',
      'To: <sip:b@example.com>',
      'Call-ID: sip-i-anm-001',
      'CSeq: 2 NOTIFY',
      'Content-Type: application/isup',
      `Content-Length: ${isup.length}`,
    ]
    const buf = new TextEncoder().encode(`${headers.join('\r\n')}\r\n\r\n`)
    const full = new Uint8Array(buf.length + isup.length)
    full.set(buf, 0)
    full.set(isup, buf.length)
    const stream = parseSipMessages(full)
    const plan = planSipBodyOperations(stream.messages[0]!.message, full)
    expect(plan.coverage.some((c) => c.protocol === 'sip-isup-number')).toBe(true)
    expect(plan.issues.some((i) => i.includes('isup-unsupported-type'))).toBe(false)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 5060, 5060, full)
    const mapping = new SessionMapping(undefined, { seed: 'v16-sipi-anm' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('111222333')).toBe(false)
  })
})

describe('V16 SMPP session graph (T52)', () => {
  it('correlates submit_sm_resp message_id with delivery receipt TLV', () => {
    resetProtocolGraphStateRegistryForTests()
    const mapping = new SessionMapping(undefined, { seed: 'v16-smpp-graph' })
    const session = smppTransportSessionForMapping(mapping, 'tcp:1')
    session.accountScope = 'acct-a'
    session.graph.noteSubmit('acct-a', 'mid-abc', 1)
    const fact = session.graph.noteDeliver('acct-a', 'mid-abc', 9, 2)
    expect(fact?.submitPacketIndex).toBe(1)
    expect(fact?.deliverPacketIndex).toBe(9)
  })
})

describe('V16 AMI EventList (T50)', () => {
  it('tracks EventList start/listitems/complete', () => {
    resetProtocolGraphStateRegistryForTests()
    const t = new AmiEventListTracker()
    t.start('act-1', 2)
    expect(t.event('act-1')?.received).toBe(1)
    expect(t.event('act-1')?.complete).toBe(true)
    const ami = [
      'Action: ListCommands',
      'ActionID: act-1',
      'EventList: start',
      'ListItems: 1',
      '',
    ].join('\r\n')
    const payload = new TextEncoder().encode(ami)
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 5038, 1, payload)
    const result = sanitizePacket(
      packetInput(pkt),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 'v16-ami-el' }),
    )
    expect(result.issues?.some((i) => i.includes('eventlist'))).toBe(true)
  })
})
