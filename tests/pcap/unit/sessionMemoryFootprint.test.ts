/**
 * Retained-memory regressions for the processing session (225k-packet capture went from ~3.2 GB
 * to ~0.5 GB Node heap). Each case pins one mechanism; behaviour (exported bytes) is unchanged —
 * that part is covered by the export pipeline / voip gates. Synthetic packets only.
 */

import { describe, expect, it } from 'vitest'
import { CaptureFormat, type PacketEnvelope } from '../../../src/pcap/domain/types'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { processCapture } from '../../../src/pcap/processing/processingPipeline'
import { policyFromPreset } from '../../../src/pcap/sanitize/engine'
import { SemanticJournalBuilder } from '../../../src/pcap/kernel/journal'
import { SessionBudgetAccountant } from '../../../src/pcap/kernel/budgets'
import { renderSymbolicOperations, type SymbolicOperation } from '../../../src/pcap/kernel/operations'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { createMaskFill } from '../../../src/pcap/sanitize/maskFill'
import { internSharedOp, internString, openIdentityInternScope } from '../../../src/pcap/kernel/identityIntern'
import { buildEthIpUdp, buildSipInviteWithSdp, envelope, VOIP_SEED } from '../fixtures/voipCorpus'

function rtp(seq: number): Uint8Array {
  const buf = new Uint8Array(172)
  buf[0] = 0x80
  buf[1] = 0x00 // PCMU
  buf[2] = (seq >> 8) & 0xff
  buf[3] = seq & 0xff
  buf.set([0x11, 0x22, 0x33, 0x44], 8) // SSRC
  return buf
}

/** RTP with a one-byte header extension (RFC 8285, id=1 len=1) — value byte at frame offset 59. */
function rtpWithOneByteExtension(seq: number): Uint8Array {
  const buf = new Uint8Array(12 + 8 + 40)
  buf[0] = 0x90 // V=2, X=1
  buf[2] = (seq >> 8) & 0xff
  buf[3] = seq & 0xff
  buf.set([0x11, 0x22, 0x33, 0x44], 8)
  buf.set([0xbe, 0xde, 0x00, 0x01], 12)
  buf.set([0x10, 0x7f, 0x00, 0x00], 16)
  return buf
}
const EXTENSION_VALUE_OFFSET = 14 + 20 + 8 + 12 + 4 + 1

async function processVoipCall(
  rtpCount = 2,
  payload: (seq: number) => Uint8Array = rtp,
  isCancelled?: () => boolean,
) {
  const src = VOIP_SEED.ip.split('.').map(Number)
  const dst = [10, 0, 0, 2]
  const packets: PacketEnvelope[] = [envelope(buildEthIpUdp(src, dst, 5060, 5060, buildSipInviteWithSdp()), 0)]
  for (let i = 1; i <= rtpCount; i++) {
    packets.push(envelope(buildEthIpUdp(src, dst, VOIP_SEED.mediaPort, 40000, payload(i)), i))
  }
  const buffer = writeClassicPcap({
    header: {
      format: CaptureFormat.ClassicPcap,
      endian: 0,
      timestampResolution: 0,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    },
    packets,
  })
  return processCapture({
    blob: new Blob([buffer]),
    fileName: 'memory.pcap',
    format: CaptureFormat.ClassicPcap,
    policy: policyFromPreset('diagnostic'),
    generationId: 'g-memory',
    sourceId: 's-memory',
    isCancelled,
  })
}

describe('processing session memory footprint', () => {
  it('RTP SSRC is a journal map op, so RTP plans carry no legacy resolve closure', async () => {
    const session = await processVoipCall()
    for (const i of [1, 2]) {
      const plan = session.discovery.packetDiscovery[i]!.frozenPlan!
      expect(plan.legacyResolve).toBeUndefined()
      expect(plan.ops.some((op) => op.kind === 'map' && op.category === 'ssrc')).toBe(true)
    }
  })

  it('identical ops of packets in one flow are the same objects', async () => {
    const session = await processVoipCall()
    const a = session.discovery.packetDiscovery[1]!.frozenPlan!.ops
    const b = session.discovery.packetDiscovery[2]!.frozenPlan!.ops
    const ssrcA = a.find((op) => op.kind === 'map' && op.category === 'ssrc')
    const ssrcB = b.find((op) => op.kind === 'map' && op.category === 'ssrc')
    expect(ssrcA).toBeDefined()
    expect(ssrcB).toBe(ssrcA)
    // Coverage lists of same-shape packets are shared too.
    expect(session.discovery.packetDiscovery[2]!.coverage).toBe(session.discovery.packetDiscovery[1]!.coverage)
  })

  it('per-packet hint maps are dropped after merging into the session maps', async () => {
    const session = await processVoipCall()
    expect(session.discovery.packetDiscovery.every((pd) => pd.portFlowHints === undefined)).toBe(true)
    expect(session.discovery.portFlowHints.size).toBeGreaterThan(0)
  })

  it('eager RTP masks survive freezing even when their fill bytes are all zero', async () => {
    // A 1-byte mask fill is 0x00 for ~1 in 256 packets; filtering placeholders by content
    // dropped exactly those masks and exported the original extension value.
    const session = await processVoipCall(600, rtpWithOneByteExtension)
    const uncovered: number[] = []
    for (let i = 1; i <= 600; i++) {
      const plan = session.discovery.packetDiscovery[i]!.frozenPlan!
      expect(plan.legacyResolve).toBeUndefined()
      const covered = plan.ops.some((op) => {
        if (op.kind === 'checksum') return false
        const length = op.kind === 'fixed' ? op.data.length : op.length
        return op.offset <= EXTENSION_VALUE_OFFSET && EXTENSION_VALUE_OFFSET < op.offset + length
      })
      if (!covered) uncovered.push(i)
    }
    expect(uncovered).toEqual([])
  })

  it('the worker session keeps no UI-only projections', async () => {
    const session = await processVoipCall()
    expect('unifiedCoverage' in session.discovery).toBe(false)
    expect('exactOccurrences' in session.discovery).toBe(false)
  })
})

describe('identity intern scope', () => {
  const op = (packetIndex: number): SymbolicOperation => ({
    kind: 'mask',
    packetIndex,
    offset: 42,
    length: 4,
    fillKind: 'domain-stream',
    domain: 'media-opaque:rtp',
    reasonCode: 'symbolized-mask',
  })

  it('interns nothing outside a run and forgets everything when the run closes', () => {
    const first = op(1)
    expect(internSharedOp(first, 1)).toBe(first)
    expect(internSharedOp(op(2), 2)).not.toBe(first) // no scope: nothing retained
    const scope = openIdentityInternScope()
    expect(internSharedOp(first, 1)).toBe(first)
    expect(internSharedOp(op(2), 2)).toBe(first)
    scope.close()
    scope.close() // idempotent
    const later = op(3)
    expect(internSharedOp(later, 3)).toBe(later)
    const spelling = ['10.0.0', '1'].join('.')
    expect(internString(spelling)).toBe(spelling)
  })

  it('a cancelled capture run closes its scope', async () => {
    let checks = 0
    await expect(processVoipCall(2, rtp, () => ++checks > 2)).rejects.toThrow('cancelled')
    const first = op(1)
    internSharedOp(first, 1)
    const second = op(2)
    expect(internSharedOp(second, 2)).toBe(second)
  })
})

describe('shared ops render with the plan packet index', () => {
  it('a mask op created for packet 1 renders packet 2 fill when the plan says so', () => {
    const op: SymbolicOperation = {
      kind: 'mask',
      packetIndex: 1,
      offset: 42,
      length: 16,
      fillKind: 'domain-stream',
      domain: 'media-opaque:rtp',
      reasonCode: 'symbolized-mask',
    }
    const [patch] = renderSymbolicOperations([op], {
      packetIndex: 2,
      mapping: new SessionMapping(undefined, { seed: 'render-packet-index' }),
      fingerprints: new FingerprintSession('render-packet-index'),
    })
    const expected = createMaskFill({ length: 16, packetIndex: 2, offset: 42, domain: 'media-opaque:rtp' })
    expect(Array.from(patch!.data)).toEqual(Array.from(expected))
  })
})

describe('journal budget counts journal-owned bytes', () => {
  it('a shared op is budgeted once, not per packet', () => {
    const budgets = new SessionBudgetAccountant()
    const journal = new SemanticJournalBuilder('g', 's', budgets)
    const shared: SymbolicOperation = {
      kind: 'map',
      packetIndex: 0,
      offset: 26,
      length: 4,
      category: 'ipv4',
      canonical: '192.0.2.1',
      constraint: { kind: 'ipv4-wire' },
      encoder: 'ipv4-octets',
    }
    const record = (packetIndex: number) => ({
      packetIndex,
      packetNumber: packetIndex + 1,
      bufferLength: 60,
      drop: false,
      coverage: [],
      issues: [],
      intents: [],
      ops: [shared],
      factIds: [],
    })
    journal.addPacket(record(0))
    const first = budgets.snapshot().journalBytes
    journal.addPacket(record(1))
    const second = budgets.snapshot().journalBytes - first
    expect(second).toBeLessThan(first)
    expect(second).toBeGreaterThan(0) // the record and its own ops array still count
  })
})
