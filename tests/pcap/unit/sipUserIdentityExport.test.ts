import { describe, expect, it } from 'vitest'
import { MappingAuthority } from '../../../src/mapping/mappingAuthority'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import { writeClassicPcap } from '../../../src/pcap/capture/pcapWriter'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { processCapture, buildPlanFromSession, identitiesFromDiscovery } from '../../../src/pcap/processing/processingPipeline'
import { createPresetProfile, profileToSanitizationPolicy } from '../../../src/pcap/profile/presets'
import { resolveSnapshotWithMappingClosure } from '../../../src/pcap/plan/mappingClosureValidation'
import { runIncrementalExport } from '../../../src/pcap/export/incremental/incrementalExportEngine'
import { previewBytesFromPlan } from '../../../src/pcap/export/packetBuilder'
import { buildEthIpUdp, envelope } from '../fixtures/voipCorpus'
import { classicHeader } from '../helpers/diagnosticPipeline'
import { assertPacketChecksumsValid } from '../helpers/checksumAssert'

describe('short SIP identities on the production processing/export path', () => {
  it.each(['diagnostic', 'high-privacy'] as const)('%s preserves distinct users and URI relationships', async level => {
    const message = [
      'INVITE sip:6001@192.168.10.10 SIP/2.0',
      'Via: SIP/2.0/UDP 192.168.10.10:5060;branch=z9hG4bK-short-users',
      'From: <sip:6000@192.168.10.10>;tag=short-user-a',
      'To: <sip:6001@192.168.10.10>',
      'Contact: <sip:6000@192.168.10.10:5060>',
      'Call-ID: short-users-synthetic',
      'CSeq: 1 INVITE',
      'Content-Length: 0', '', '',
    ].join('\r\n')
    const frame = buildEthIpUdp([192, 168, 10, 10], [192, 168, 10, 11], 5060, 5060, new TextEncoder().encode(message))
    // Repeated packet also verifies stable rendering across retransmissions.
    const packets = [envelope(frame, 0), envelope(frame.slice(), 1)]
    const blob = new Blob([writeClassicPcap({ header: classicHeader(), packets })])
    const generationId = 'short-user-export'
    const sourceId = 'synthetic'
    const profile = createPresetProfile(level)
    const session = await processCapture({ blob, fileName: 'synthetic.pcap', format: CaptureFormat.ClassicPcap,
      policy: profileToSanitizationPolicy(profile), generationId, sourceId })
    const authority = new MappingAuthority(profile.mapping)
    const { snapshot, unresolvedFailures } = await resolveSnapshotWithMappingClosure({
      generationId, sourceId, identities: identitiesFromDiscovery(session.discovery), intents: session.discovery.intents,
      resolve: async identities => {
        const result = authority.resolve({ generationId, sourceId, identities })
        if (!result.ok) throw new Error(result.code)
        return result.snapshot
      },
    })
    expect(unresolvedFailures).toEqual([])
    expect(snapshot.overflow).toBe(false)
    const plan = buildPlanFromSession(session, snapshot, profile)
    const built = await runIncrementalExport({ plan, descriptors: session.descriptors, sourceBlob: blob })
    expect(built.validationValid).toBe(true)
    expect(plan.incidents?.totalFailures ?? 0).toBe(0)
    const exported = readClassicPcap(await new Blob([...built.chunks]).arrayBuffer())
    expect(exported.packets).toHaveLength(2)
    const payloads = exported.packets.map(packet => new TextDecoder().decode(packet.data.subarray(42)))
    expect(payloads[1]).toBe(payloads[0])
    const payload = payloads[0]!
    const from = /^From: <sip:([^@]+)@([^>]+)>/m.exec(payload)!
    const to = /^To: <sip:([^@]+)@([^>]+)>/m.exec(payload)!
    const request = /^INVITE sip:([^@]+)@([^ ]+)/m.exec(payload)!
    const contact = /^Contact: <sip:([^@]+)@/m.exec(payload)!
    expect(from[1]).toHaveLength(4)
    expect(to[1]).toHaveLength(4)
    expect(from[1]).not.toBe(to[1])
    expect(from[2]).toBe(to[2])
    expect(request[1]).toBe(to[1])
    expect(request[2]).toBe(to[2])
    expect(contact[1]).toBe(from[1])
    expect(payload).not.toMatch(/600[01]/)
    for (const [i, packet] of exported.packets.entries()) {
      assertPacketChecksumsValid(packet.data, packet.linkType)
      const preview = previewBytesFromPlan(packets[i]!, plan.packets[i]!)
      // Checksums are finalized on export; SIP bytes must already match the preview.
      expect(packet.data.subarray(42)).toEqual(preview.subarray(42))
    }
  })
})
