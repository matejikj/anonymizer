/**
 * R09 — frozen SemanticJournal on ProcessingSession; journal-backed plan path where ops exist.
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import {
  buildPlanFromSession,
  processCapture,
} from '../../../src/pcap/processing/processingPipeline'
import { frozenPlansFromJournal, KERNEL_ENGINE_VERSION } from '../../../src/pcap/kernel'
import { frozenPlanFromJournalRecord } from '../../../src/pcap/kernel/journal'
import { resolveFrozenPacketPlan } from '../../../src/pcap/kernel/frozenPlan'
import { planWireSignature } from '../../../src/pcap/plan/deterministicPlanBuilder'
import { SnapshotMappingAdapter } from '../../../src/pcap/plan/snapshotMappingAdapter'
import { policyFromPreset } from '../../../src/pcap/sanitize/engine'
import { createPresetProfile } from '../../../src/pcap/profile/presets'
import type { MappingSnapshot } from '../../../src/mapping/types'
import { generateClassicPcap } from '../fixtures/generate'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import { identitiesFromDiscovery } from '../../../src/pcap/discovery/discoveryPipeline'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { STUN_ATTR, STUN_MAGIC_COOKIE } from '../../../src/pcap/protocols/application/stun/classify'

describe('R09 shared pipeline journal', () => {
  it('processCapture exposes frozen journal aligned with discovery', async () => {
    const ab = generateClassicPcap(8, 128)
    const session = await processCapture({
      blob: new Blob([ab]),
      fileName: 'r09.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('diagnostic'),
      generationId: 'r09-gen',
      sourceId: 'r09-src',
    })

    expect(session.packets).toBeUndefined()
    expect(session.journal.generationId).toBe('r09-gen')
    expect(session.journal.sourceId).toBe('r09-src')
    expect(session.journal.engineVersion).toBe(KERNEL_ENGINE_VERSION)
    expect(session.journal.packets.length).toBe(8)
    expect(frozenPlansFromJournal(session.journal).length).toBe(8)
    expect(session.journal.packets.map((p) => p.packetIndex)).toEqual([0, 1, 2, 3, 4, 5, 6, 7])
    expect(session.discovery.packetDiscovery.length).toBe(8)
  })

  it('buildPlanFromSession stays bit-stable when journal backs resolvable ops', async () => {
    const ab = generateClassicPcap(4, 96)
    const session = await processCapture({
      blob: new Blob([ab]),
      fileName: 'r09-plan.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('high-privacy'),
      generationId: 'r09-plan-gen',
      sourceId: 'r09-plan-src',
    })

    const profile = createPresetProfile('high-privacy', { id: 'r09-plan', name: 'R09 plan' })
    const snapshot: MappingSnapshot = {
      scope: 'session',
      revision: 0,
      mappingRevision: 0,
      canonicalizationVersion: 1,
      generationId: 'r09-plan-gen',
      sourceId: 'r09-plan-src',
      overflow: false,
      entries: [],
    }

    const plan = buildPlanFromSession(session, snapshot, profile)
    expect(plan.packets.length).toBe(4)
    expect(planWireSignature(plan).length).toBeGreaterThan(0)
    expect(session.journal.packets.length).toBe(4)
  })

  it('DNS unknown RDATA projects journal mask ops through processCapture', async () => {
    const dnsPayload = buildDnsUnknownRdataAnswer([0xde, 0xad, 0xbe, 0xef])
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 53, 53, dnsPayload)
    const pcap = classicPcapOnePacket(frame)
    const session = await processCapture({
      blob: new Blob([pcap]),
      fileName: 'r09-dns-mask.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('high-privacy'),
      generationId: 'r09-dns-mask-gen',
      sourceId: 'r09-dns-mask.pcap',
    })

    const journalRec = session.journal.packets[0]
    expect(journalRec?.ops.some((o) => o.kind === 'mask' && o.domain === 'dns-rdata:153')).toBe(true)
    expect(frozenPlanFromJournalRecord(journalRec!).legacyResolve).toBeUndefined()
  })

  it('DNS A deferred map mirrors journal ops for plan resolve without legacy bridge', async () => {
    const dnsAnswer = buildDnsAResponse([192, 168, 1, 50])
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 53, 53, dnsAnswer)
    const pcap = classicPcapOnePacket(frame)
    const fileName = 'r09-dns-a.pcap'
    const generationId = 'r09-dns-gen'
    const session = await processCapture({
      blob: new Blob([pcap]),
      fileName,
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('high-privacy'),
      generationId,
      sourceId: fileName,
    })

    const journalRec = session.journal.packets.find((p) =>
      p.ops.some((o) => o.kind === 'map' && o.category === 'ipv4'),
    )
    expect(journalRec).toBeDefined()

    const journalPlan = frozenPlanFromJournalRecord(journalRec!)
    expect(journalPlan.legacyResolve).toBeUndefined()
    expect(journalPlan.ops.some((o) => o.kind === 'map' && o.category === 'ipv4')).toBe(true)

    const profile = createPresetProfile('high-privacy', { id: 'r09-dns', name: 'R09 DNS' })
    const authority = new MappingAuthority(
      {
        ip: profile.mapping.ip,
        mac: profile.mapping.mac,
        timestamps: profile.mapping.timestamps,
        ephemeralPorts: profile.mapping.ephemeralPorts,
        contentSignalingPorts: profile.mapping.contentSignalingPorts,
        vlan: profile.mapping.vlan,
      },
      { seed: 'r09-dns-journal' },
    )
    const identities = identitiesFromDiscovery(session.discovery)
    const resolved = authority.resolve({ generationId, sourceId: fileName, identities })
    expect(resolved.ok).toBe(true)
    if (!resolved.ok) return

    const ctx = {
      mapping: new SnapshotMappingAdapter(resolved.snapshot),
      fingerprints: new FingerprintSession(generationId),
      packetIndex: journalRec!.packetIndex,
      packetNumber: journalRec!.packetNumber,
    }
    const patches = resolveFrozenPacketPlan(journalPlan, ctx)
    const mapOp = journalRec!.ops.find((o) => o.kind === 'map' && o.category === 'ipv4')
    expect(mapOp?.kind).toBe('map')
    const ipPatch = patches.find((p) => p.offset === mapOp!.offset)
    expect(ipPatch).toBeDefined()
    expect([...ipPatch!.data]).not.toEqual([192, 168, 1, 50])

    const plan = buildPlanFromSession(session, resolved.snapshot, profile)
    const planPatch = plan.packets[journalRec!.packetIndex]?.patches.find(
      (p) => p.offset === mapOp!.offset,
    )
    expect(planPatch?.data).toEqual(ipPatch!.data)
  })

  it('RADIUS Framed-IP deferred map mirrors journal ops', async () => {
    const radiusPayload = buildRadiusFramedIp([192, 168, 50, 1])
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1812, 1812, radiusPayload)
    const pcap = classicPcapOnePacket(frame)
    const session = await processCapture({
      blob: new Blob([pcap]),
      fileName: 'r09-radius.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('high-privacy'),
      generationId: 'r09-radius-gen',
      sourceId: 'r09-radius.pcap',
    })

    const framedOp = session.journal.packets
      .flatMap((p) => p.ops)
      .find((o) => o.kind === 'map' && o.category === 'ipv4' && o.canonical === '192.168.50.1')
    expect(framedOp).toBeDefined()
    expect(framedOp).toMatchObject({
      encoder: 'ipv4-octets',
      constraint: { kind: 'ipv4-wire' },
    })
    const journalRec = session.journal.packets.find((p) =>
      p.ops.some((o) => o === framedOp),
    )
    expect(journalRec).toBeDefined()
    const journalPlan = frozenPlanFromJournalRecord(journalRec!)
    expect(journalPlan.legacyResolve).toBeUndefined()
  })

  it('STUN XOR-MAPPED deferred map mirrors journal ops', async () => {
    const stun = buildStunXorMappedIpv4([203, 0, 113, 50], 54320)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 54320, 3478, stun)
    const pcap = classicPcapOnePacket(frame)
    const session = await processCapture({
      blob: new Blob([pcap]),
      fileName: 'r09-stun.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('high-privacy'),
      generationId: 'r09-stun-gen',
      sourceId: 'r09-stun.pcap',
    })

    const journalRec = session.journal.packets.find((p) =>
      p.ops.some((o) => o.kind === 'map' && o.category === 'ipv4'),
    )
    expect(journalRec).toBeDefined()
    const mapOp = journalRec!.ops.find((o) => o.kind === 'map' && o.category === 'ipv4')
    expect(mapOp).toMatchObject({ encoder: 'ipv4-octets', constraint: { kind: 'ipv4-wire' } })
  })
})

function buildRadiusFramedIp(ipv4: number[]): Uint8Array {
  const pkt = new Uint8Array(20 + 6)
  pkt[0] = 1 // Access-Request
  pkt[1] = 42
  const total = pkt.length
  pkt[2] = (total >> 8) & 0xff
  pkt[3] = total & 0xff
  pkt[20] = 8 // Framed-IP-Address
  pkt[21] = 6
  pkt.set(ipv4, 22)
  return pkt
}

function buildStunXorMappedIpv4(ip: number[], port: number): Uint8Array {
  const xPort = (port ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xffff)) & 0xffff
  const xorIp = new Uint8Array([
    ip[0]! ^ ((STUN_MAGIC_COOKIE >>> 24) & 0xff),
    ip[1]! ^ ((STUN_MAGIC_COOKIE >>> 16) & 0xff),
    ip[2]! ^ ((STUN_MAGIC_COOKIE >>> 8) & 0xff),
    ip[3]! ^ (STUN_MAGIC_COOKIE & 0xff),
  ])
  const attrValue = new Uint8Array(8)
  attrValue[1] = 0x01
  attrValue[2] = (xPort >> 8) & 0xff
  attrValue[3] = xPort & 0xff
  attrValue.set(xorIp, 4)
  const bodyLen = 4 + 8
  const msg = new Uint8Array(20 + bodyLen)
  msg[0] = 0x01
  msg[1] = 0x01
  msg[2] = (bodyLen >> 8) & 0xff
  msg[3] = bodyLen & 0xff
  msg[4] = (STUN_MAGIC_COOKIE >>> 24) & 0xff
  msg[5] = (STUN_MAGIC_COOKIE >>> 16) & 0xff
  msg[6] = (STUN_MAGIC_COOKIE >>> 8) & 0xff
  msg[7] = STUN_MAGIC_COOKIE & 0xff
  msg[8] = 0x01
  msg[20] = (STUN_ATTR.XOR_MAPPED_ADDRESS >> 8) & 0xff
  msg[21] = STUN_ATTR.XOR_MAPPED_ADDRESS & 0xff
  msg[22] = 0x00
  msg[23] = 0x08
  msg.set(attrValue, 24)
  return msg
}

function encodeDnsName(labels: string[]): number[] {
  const bytes: number[] = []
  for (const label of labels) {
    bytes.push(label.length)
    for (const ch of label) bytes.push(ch.charCodeAt(0))
  }
  bytes.push(0)
  return bytes
}

/** Minimal DNS response: one A RR in ANSWER (no QUESTION). */
function buildDnsUnknownRdataAnswer(rdata: number[]): Uint8Array {
  const name = encodeDnsName(['host'])
  return new Uint8Array([
    0x00, 0x02,
    0x84, 0x00,
    0x00, 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    ...name,
    0x00, 0x99,
    0x00, 0x01,
    0x00, 0x00, 0x01, 0x2c,
    (rdata.length >> 8) & 0xff,
    rdata.length & 0xff,
    ...rdata,
  ])
}

function buildDnsAResponse(ipv4: number[]): Uint8Array {
  const name = encodeDnsName(['host', 'example', 'com'])
  return new Uint8Array([
    0x00, 0x01, // transaction id
    0x84, 0x00, // response, authoritative
    0x00, 0x00, // QDCOUNT
    0x00, 0x01, // ANCOUNT
    0x00, 0x00,
    0x00, 0x00,
    ...name,
    0x00, 0x01, // A
    0x00, 0x01, // IN
    0x00, 0x00, 0x01, 0x2c, // TTL
    0x00, 0x04, // RDLENGTH
    ...ipv4,
  ])
}

function classicPcapOnePacket(frame: Uint8Array): ArrayBuffer {
  const global = new Uint8Array(24)
  const gv = new DataView(global.buffer)
  gv.setUint32(0, 0xa1b2c3d4, true)
  gv.setUint16(4, 2, true)
  gv.setUint16(6, 4, true)
  gv.setUint32(16, 65535, true)
  gv.setUint32(20, 1, true)

  const rec = new Uint8Array(16 + frame.length)
  const rv = new DataView(rec.buffer)
  rv.setUint32(0, 1_700_000_000, true)
  rv.setUint32(4, 0, true)
  rv.setUint32(8, frame.length, true)
  rv.setUint32(12, frame.length, true)
  rec.set(frame, 16)

  const out = new Uint8Array(global.length + rec.length)
  out.set(global, 0)
  out.set(rec, global.length)
  return out.buffer
}
