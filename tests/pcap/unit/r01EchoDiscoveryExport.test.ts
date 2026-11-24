/**
 * R01 — kernel map ops must not bake Passthrough originals into a real PCAP export.
 * Full discovery → MappingAuthority.resolve → plan → buildCaptureFromPlan path.
 */
import { describe, expect, it } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import {
  buildEchoUdpDatagram,
  ECHO_UDP_EXAMPLE_PORT,
} from '../../../src/pcap/kernel/onboarding/echoUdpExample'
import { runDiagnosticExportPipeline } from '../helpers/diagnosticPipeline'
import { buildEthIpUdp } from '../fixtures/voipCorpus'

function envelope(data: Uint8Array, index = 0): PacketEnvelope {
  return {
    packetNumber: index,
    timestamp: {
      ticks: 1_700_000_000_000_000n + BigInt(index),
      unitsPerSecond: 1_000_000n,
      offsetSeconds: 0n,
    },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 24,
    data,
  }
}

describe('R01 kernel ECHO discovery→plan→export', () => {
  it('maps radio-id and masks payload; originals absent from export bytes', () => {
    const radioId = 0x414243 // ASCII "ABC" on the wire if left unmapped
    const canary = 'AUDIT_ECHO_CONTENT'
    const payload = buildEchoUdpDatagram(radioId, new TextEncoder().encode(canary))
    const frame = buildEthIpUdp(
      [10, 0, 0, 1],
      [10, 0, 0, 2],
      ECHO_UDP_EXAMPLE_PORT,
      ECHO_UDP_EXAMPLE_PORT,
      payload,
    )
    const { built, discovery } = runDiagnosticExportPipeline(
      [envelope(frame)],
      'r01-echo.pcap',
      'r01-echo',
      { mappingSeed: 'r01-echo-export' },
    )

    expect(built.validationValid).toBe(true)
    expect(discovery.packetDiscovery[0]?.coverage.some((c) => c.protocol === 'echo-udp-example')).toBe(
      true,
    )

    const exported = built.packets[0]!.data
    const appOff = 14 + 20 + 8
    expect(Array.from(exported.subarray(appOff, appOff + 4))).toEqual([0x45, 0x43, 0x48, 0x4f]) // ECHO
    const wireId = Array.from(exported.subarray(appOff + 4, appOff + 7))
    expect(wireId).not.toEqual([0x41, 0x42, 0x43])
    const latin1 = new TextDecoder('latin1').decode(exported)
    expect(latin1.includes(canary)).toBe(false)
    expect(latin1.includes('ABC')).toBe(false)
  })
})
