/**
 * R08 — AMI / Q.931 / SMPP scoped graphs + session lifecycle integration.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { sanitizeAmi } from '../../../src/pcap/sanitize/asterisk/ami'
import {
  AmiEventListTracker,
  amiEventListTrackerForTransport,
} from '../../../src/pcap/sanitize/asterisk/amiEventList'
import { sanitizeQ931 } from '../../../src/pcap/sanitize/isdn/q931'
import { q931CallGraphForMapping } from '../../../src/pcap/sanitize/isdn/q931CallGraph'
import { sanitizeSmpp } from '../../../src/pcap/sanitize/smpp'
import { smppTransportSessionForMapping } from '../../../src/pcap/sanitize/smpp/smppSessionGraph'
import {
  disposeProtocolGraphStateForSession,
  protocolGraphCaptureGeneration,
  resetProtocolGraphStateRegistryForTests,
} from '../../../src/pcap/sanitize/protocolGraphState'

function buildMinimalQ931(callRef: number, msgType: number): Uint8Array {
  return Uint8Array.of(0x08, 0x01, callRef & 0x7f, msgType)
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

function wrapSmppPdu(commandId: number, status: number, body: Uint8Array): Uint8Array {
  const len = 16 + body.length
  const out = new Uint8Array(len)
  writeU32(out, 0, len)
  writeU32(out, 4, commandId)
  writeU32(out, 8, status)
  writeU32(out, 12, 1)
  out.set(body, 16)
  return out
}

describe('R08 AMI EventList', () => {
  it('isolates EventList trackers per TCP transport scope', () => {
    resetProtocolGraphStateRegistryForTests()
    const mapping = new SessionMapping(undefined, { seed: 'r08-ami-scope' })
    const left = amiEventListTrackerForTransport(mapping, 'tcp:10.0.0.1:5038<->10.0.0.2:5038')
    const right = amiEventListTrackerForTransport(mapping, 'tcp:10.0.0.3:5038<->10.0.0.4:5038')
    left.start('shared-action', 1)
    right.start('shared-action', 1)
    expect(right.event('shared-action')?.received).toBe(1)
    expect(left.event('shared-action')?.received).toBe(1)
  })

  it('counts child events after EventList Complete (terminal) via sanitize path', () => {
    resetProtocolGraphStateRegistryForTests()
    const mapping = new SessionMapping(undefined, { seed: 'r08-ami-el' })
    const collector = new PatchCollector()
    const transport = 'tcp:192.0.2.1:5038<->192.0.2.2:5038'
    const start = [
      'Response: Success',
      'ActionID: act-99',
      'EventList: start',
      'ListItems: 2',
      '',
    ].join('\r\n')
    sanitizeAmi(
      new TextEncoder().encode(start),
      0,
      start.length,
      5038,
      40000,
      collector,
      mapping,
      1,
      false,
      undefined,
      { transportSessionKey: transport },
    )
    const child = [
      'Event: Newchannel',
      'ActionID: act-99',
      'Channel: PJSIP/test-00000001',
      '',
    ].join('\r\n')
    const childResult = sanitizeAmi(
      new TextEncoder().encode(child),
      0,
      child.length,
      5038,
      40000,
      new PatchCollector(),
      mapping,
      2,
      false,
      undefined,
      { transportSessionKey: transport },
    )
    expect(childResult?.issues).toContain('ami-eventlist-child')
  })

  it('EventList complete does not erase pending child events', () => {
    const t = new AmiEventListTracker()
    t.start('act', 1)
    t.complete('act')
    expect(t.event('act')?.complete).toBe(true)
  })
})

describe('R08 Q.931 multi-link graph', () => {
  it('flags same call reference on different link scopes', () => {
    resetProtocolGraphStateRegistryForTests()
    const mapping = new SessionMapping(undefined, { seed: 'r08-q931' })
    const collector = new PatchCollector()
    const cap = `${protocolGraphCaptureGeneration()}/cap/q931`
    const linkA = 'lapd:sapi=0:tei=1'
    const linkB = 'lapd:sapi=0:tei=2'
    const pdu = buildMinimalQ931(0x05, 0x05)
    const first = sanitizeQ931(
      pdu,
      0,
      pdu.length,
      collector,
      mapping,
      undefined,
      0,
      'q931',
      { linkScope: linkA, captureScopeKey: cap },
    )
    expect(first?.issues?.includes('q931-multi-link-graph')).toBe(false)
    const second = sanitizeQ931(
      pdu,
      0,
      pdu.length,
      new PatchCollector(),
      mapping,
      undefined,
      1,
      'q931',
      { linkScope: linkB, captureScopeKey: cap },
    )
    expect(second?.issues).toContain('q931-multi-link-graph')
  })

  it('bounds messageTypes history per call node', () => {
    resetProtocolGraphStateRegistryForTests()
    const mapping = new SessionMapping(undefined, { seed: 'r08-q931-bound' })
    const graph = q931CallGraphForMapping(mapping, '0/test/q931')
    const link = 'lapd:sapi=0:tei=9'
    for (let i = 0; i < 40; i++) {
      graph.observe(link, 7, i & 0xff, i)
    }
    const node = graph.observe(link, 7, 0x7f, 40)
    expect(node.node.messageTypes.length).toBeLessThanOrEqual(32)
  })
})

describe('R08 SMPP account/session scope', () => {
  it('does not correlate message_id across different account scopes', () => {
    resetProtocolGraphStateRegistryForTests()
    const mapping = new SessionMapping(undefined, { seed: 'r08-smpp' })
    const tcpA = 'tcp:10.0.0.1:2775<->10.0.0.2:2775'
    const tcpB = 'tcp:10.0.0.3:2775<->10.0.0.4:2775'
    const sessionA = smppTransportSessionForMapping(mapping, tcpA)
    sessionA.accountScope = 'smsc-alpha'
    sessionA.graph.noteSubmit('smsc-alpha', 'dup-mid', 1)
    const sessionB = smppTransportSessionForMapping(mapping, tcpB)
    sessionB.accountScope = 'smsc-beta'
    expect(sessionB.graph.noteDeliver('smsc-beta', 'dup-mid', 3)).toBeNull()
    expect(sessionA.graph.noteDeliver('smsc-alpha', 'dup-mid', 4)).not.toBeNull()
  })

  it('uses bind system_id as accountScope in sanitize path', () => {
    resetProtocolGraphStateRegistryForTests()
    const mapping = new SessionMapping(undefined, { seed: 'r08-smpp-bind' })
    const transport = 'tcp:192.0.2.10:2775<->192.0.2.20:2775'
    const bindBody = new Uint8Array([
      ...cOctet('acct-gamma'),
      ...cOctet('secret'),
      ...cOctet(''),
      0x34,
      0x00,
      0x00,
      ...cOctet(''),
    ])
    const bindPdu = wrapSmppPdu(0x00000002, 0, bindBody)
    sanitizeSmpp(
      bindPdu,
      0,
      bindPdu.length,
      new PatchCollector(),
      mapping,
      undefined,
      0,
      { transportSessionKey: transport },
    )
    const submitRespBody = cOctet('shared-mid-001')
    const submitPdu = wrapSmppPdu(0x80000004, 0, submitRespBody)
    const submitResult = sanitizeSmpp(
      submitPdu,
      0,
      submitPdu.length,
      new PatchCollector(),
      mapping,
      undefined,
      1,
      { transportSessionKey: transport },
    )
    expect(submitResult?.issues).toContain('smpp-session-submit')
    const session = smppTransportSessionForMapping(mapping, transport)
    expect(session.graph.noteDeliver('acct-gamma', 'shared-mid-001', 2)).not.toBeNull()
  })
})

describe('R08 session lifecycle dispose', () => {
  it('clears mapping-scoped graphs and bumps capture generation', () => {
    resetProtocolGraphStateRegistryForTests()
    const mapping = new SessionMapping(undefined, { seed: 'r08-dispose' })
    const genBefore = protocolGraphCaptureGeneration()
    const graph = q931CallGraphForMapping(mapping, `${genBefore}/link/q931`)
    graph.observe('lapd:sapi=0:tei=1', 3, 0x05, 0)
    disposeProtocolGraphStateForSession()
    expect(protocolGraphCaptureGeneration()).toBe(String(Number(genBefore) + 1))
    const genAfter = protocolGraphCaptureGeneration()
    const fresh = q931CallGraphForMapping(mapping, `${genAfter}/link/q931`)
    const node = fresh.observe('lapd:sapi=0:tei=1', 3, 0x05, 1)
    expect(node.node.messageTypes).toEqual([0x05])
  })
})
