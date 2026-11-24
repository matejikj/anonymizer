/**
 * T31 — RND Dispatch Lite sanitize path (descriptor pilot).
 */
import { describe, expect, it } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'
import { runDiagnosticExportPipeline } from '../helpers/diagnosticPipeline'
import {
  buildRndDispatchLiteDatagram,
  RND_DISPATCH_LITE_UDP_PORT,
} from '../../../src/pcap/protocols/descriptors/rndDispatchLite.ts'

function applyPatches(original: Uint8Array, patches: readonly { offset: number; data: Uint8Array }[]): Uint8Array {
  const out = original.slice()
  for (const p of patches) out.set(p.data, p.offset)
  return out
}

describe('T31 RND Dispatch Lite sanitize', () => {
  it('maps radio IDs and redacts text-page canary', () => {
    const body = buildRndDispatchLiteDatagram({
      msgType: 2,
      srcRadioId: 100001,
      dstRadioId: 100002,
      siteId: 0x11223344,
      body: new TextEncoder().encode('SECRET-PAGE-CANARY'),
    })
    const frame = buildEthIpUdp([10, 1, 2, 3], [10, 1, 2, 4], 40000, RND_DISPATCH_LITE_UDP_PORT, body)
    const mapping = new SessionMapping(
      {
        ip: 'topology-preserving',
        mac: 'locally-administered',
        timestamps: 'relative',
        ephemeralPorts: 'preserve',
        contentSignalingPorts: 'preserve',
        vlan: 'map',
      },
      { seed: 't31-rnd-sanitize' },
    )
    const result = sanitizePacket(
      {
        index: 0,
        data: frame,
        capturedLength: frame.length,
        originalLength: frame.length,
        linkType: 1,
      },
      DIAGNOSTIC_POLICY,
      mapping,
      { fingerprints: new FingerprintSession() },
    )
    const out = applyPatches(frame, result.patches)
    const text = new TextDecoder('utf-8', { fatal: false }).decode(out)
    expect(text).not.toContain('SECRET-PAGE-CANARY')
    expect(text).toContain('RND1')
    expect(result.coverage.some((c) => c.protocol === 'rnd-dispatch-lite' && c.status === 'covered')).toBe(
      true,
    )
  })

  it('discovery→plan→export maps radio IDs and masks page canary (R01/T31 wiring)', () => {
    const body = buildRndDispatchLiteDatagram({
      msgType: 2,
      srcRadioId: 0x414243,
      dstRadioId: 0x444546,
      siteId: 0x99887766,
      body: new TextEncoder().encode('EXPORT-CANARY-PAGE'),
    })
    const frame = buildEthIpUdp([10, 1, 2, 3], [10, 1, 2, 4], 40000, RND_DISPATCH_LITE_UDP_PORT, body)
    const envelope: PacketEnvelope = {
      packetNumber: 0,
      timestamp: { ticks: 1_700_000_000_000_000n, unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
      capturedLength: frame.length,
      originalLength: frame.length,
      linkType: 1,
      interfaceId: 0,
      sectionIndex: 0,
      fileOffset: 24,
      data: frame,
    }
    const { built, discovery } = runDiagnosticExportPipeline(
      [envelope],
      't31-rnd.pcap',
      't31-rnd-export',
      { mappingSeed: 't31-rnd-export' },
    )
    expect(built.validationValid).toBe(true)
    expect(
      discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'rnd-dispatch-lite'),
    ).toBe(true)
    const exported = built.packets[0]!.data
    const latin1 = new TextDecoder('latin1').decode(exported)
    expect(latin1.includes('EXPORT-CANARY-PAGE')).toBe(false)
    expect(latin1.includes('ABC')).toBe(false)
    expect(latin1.includes('RND1')).toBe(true)
  })
})
