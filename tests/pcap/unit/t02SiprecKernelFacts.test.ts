/**
 * T02.S4 — SIPREC rs-metadata+xml emits analytical kernel journal facts (not coverage id only).
 */

import { describe, expect, it } from 'vitest'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { processCapture } from '../../../src/pcap/processing/processingPipeline'
import { policyFromPreset } from '../../../src/pcap/sanitize/engine'
import {
  SIPREC_METADATA_PROTOCOL_ID,
  SemanticJournalBuilder,
  emitSiprecMetadataKernelFacts,
} from '../../../src/pcap/kernel'
import { classifySipPayload, parseSipMessage } from '../../../src/pcap/protocols/application/sip'
import {
  buildEthIpTcp,
  buildEthIpUdp,
  buildSipInviteWithSdp,
  buildSiprecInvite,
  envelope,
  SIPREC_SEED,
} from '../fixtures/voipCorpus'

function pcapBlob(frames: ReturnType<typeof envelope>[]): Blob {
  const buf = writeClassicPcap({
    header: {
      format: CaptureFormat.ClassicPcap,
      endian: Endian.Little,
      timestampResolution: TimestampResolution.Microseconds,
      versionMajor: 2,
      versionMinor: 4,
      snapLen: 65535,
      linkType: 1,
      tzOffset: 0,
      sigfigs: 0,
    },
    packets: frames.map((f, i) => ({
      packetNumber: i,
      timestamp: { ticks: BigInt(i), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
      capturedLength: f.data.length,
      originalLength: f.data.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 0,
      data: f.data,
    })),
  })
  return new Blob([buf])
}

describe('T02.S4 SIPREC kernel protocol facts', () => {
  it('emitSiprecMetadataKernelFacts records coverage + identity facts', () => {
    const payload = buildSiprecInvite()
    const parsed = parseSipMessage(payload)
    expect(parsed.kind).toBe('complete')
    if (parsed.kind !== 'complete') return

    const journal = new SemanticJournalBuilder('t02-s4', 'test')
    const factIds = emitSiprecMetadataKernelFacts({
      message: parsed.message,
      buffer: payload,
      packetIndex: 0,
      logicalMessageId: 0,
      journal,
    })
    expect(factIds.length).toBeGreaterThan(0)

    const frozen = journal.freeze()
    const siprecFacts = frozen.facts.filter((f) => f.protocolId === SIPREC_METADATA_PROTOCOL_ID)
    expect(siprecFacts.some((f) => f.coverageStatus === 'covered')).toBe(true)
    expect(
      siprecFacts.some((f) => f.identityRef?.canonical === SIPREC_SEED.participantAor),
    ).toBe(true)
    expect(
      siprecFacts.some((f) => f.identityRef?.canonical.startsWith('siprec-session:')),
    ).toBe(true)
    expect(frozen.facts.some((f) => f.parentFactId > 0)).toBe(true)
  })

  it('processCapture journal carries sip-siprec-metadata facts (UDP)', async () => {
    const payload = buildSiprecInvite()
    const frame = buildEthIpUdp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, payload)
    const blob = pcapBlob([envelope(frame, 0)])
    const session = await processCapture({
      blob,
      fileName: 't02-s4-udp.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('diagnostic'),
      generationId: 'g-t02-s4-udp',
      sourceId: 's-t02-s4',
    })
    expect(
      session.journal.facts.some((f) => f.protocolId === SIPREC_METADATA_PROTOCOL_ID),
    ).toBe(true)
    expect(session.journal.packets[0]?.factIds.length).toBeGreaterThan(0)
  })

  it('processCapture journal carries sip-siprec-metadata facts (TCP reassembly)', async () => {
    const payload = buildSiprecInvite({ transport: 'tcp' })
    const mid = Math.floor(payload.length / 2)
    const packets = [
      envelope(
        buildEthIpTcp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, 2000, payload.subarray(0, mid)),
        0,
      ),
      envelope(
        buildEthIpTcp([192, 168, 55, 10], [10, 0, 0, 2], 5060, 5060, 2000 + mid, payload.subarray(mid)),
        1,
      ),
    ]
    const blob = pcapBlob(packets)
    const session = await processCapture({
      blob,
      fileName: 't02-s4-tcp.pcap',
      format: CaptureFormat.ClassicPcap,
      policy: policyFromPreset('diagnostic'),
      generationId: 'g-t02-s4-tcp',
      sourceId: 's-t02-s4',
    })
    expect(
      session.journal.facts.some((f) => f.protocolId === SIPREC_METADATA_PROTOCOL_ID),
    ).toBe(true)
  })

  it('does not emit SIPREC facts for plain SDP INVITE', () => {
    const payload = buildSipInviteWithSdp()
    const journal = new SemanticJournalBuilder('t02-s4-neg', 'test')
    const classification = classifySipPayload(payload, 0, payload.length, { portHint: true })
    expect(classification.kind).toBe('complete')
    if (classification.kind !== 'complete') return
    emitSiprecMetadataKernelFacts({
      message: classification.message,
      buffer: payload,
      packetIndex: 0,
      logicalMessageId: 0,
      journal,
    })
    expect(journal.freeze().facts.some((f) => f.protocolId === SIPREC_METADATA_PROTOCOL_ID)).toBe(
      false,
    )
  })
})
