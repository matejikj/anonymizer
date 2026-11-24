/**
 * T31 — descriptor validator + registry + sanitize must-not-leak.
 */
import { describe, expect, it } from 'vitest'
import {
  assertAllDescriptorsValid,
  buildRndDispatchLiteDatagram,
  DESCRIPTOR_TEMPLATE,
  listWireProtocolDescriptors,
  rndDispatchLiteDescriptor,
  sanitizeFromDescriptor,
  validateWireProtocolDescriptor,
} from '../../src/pcap/protocols/descriptors/index.ts'
import { PatchCollector } from '../../src/pcap/sanitize/PatchCollector.ts'
import { SessionMapping } from '../../src/pcap/anonymization/mapping.ts'
import { FingerprintSession } from '../../src/pcap/anonymization/fingerprintSession.ts'
import { APPLICATION_HANDLER_ORDER } from '../../src/pcap/kernel/applicationHandlers.ts'

function mapping(): SessionMapping {
  return new SessionMapping(
    {
      ip: 'topology-preserving',
      mac: 'locally-administered',
      timestamps: 'relative',
      ephemeralPorts: 'preserve',
      contentSignalingPorts: 'preserve',
      vlan: 'map',
    },
    { seed: 't31-descriptors' },
  )
}

describe('T31 protocol descriptors', () => {
  it('ships validated descriptors including the RND Dispatch Lite pilot', () => {
    expect(() => assertAllDescriptorsValid()).not.toThrow()
    expect(listWireProtocolDescriptors().some((d) => d.id === 'rnd-dispatch-lite')).toBe(true)
    expect(validateWireProtocolDescriptor(rndDispatchLiteDescriptor).ok).toBe(true)
    expect(APPLICATION_HANDLER_ORDER.some((h) => h.id === 'rnd-dispatch-lite')).toBe(true)
  })

  it('rejects descriptor with uncovered header bytes', () => {
    const bad = {
      ...DESCRIPTOR_TEMPLATE,
      id: 'gap-test',
      framing: { ...DESCRIPTOR_TEMPLATE.framing, headerLength: 16 },
    }
    const result = validateWireProtocolDescriptor(bad)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.issues.some((i) => i.code === 'gap')).toBe(true)
  })

  it('rejects preserve without reason', () => {
    const bad = structuredClone(rndDispatchLiteDescriptor)
    const field = bad.variants[0]!.fields.find((f) => f.name === 'version')!
    ;(field as { disposition: { kind: string; reason?: string } }).disposition = {
      kind: 'preserve',
      reason: '',
    }
    const result = validateWireProtocolDescriptor(bad)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.issues.some((i) => i.code === 'preserve-without-reason')).toBe(true)
  })

  it('maps radio IDs and masks GPS/text canaries', () => {
    const canaryGps = new TextEncoder().encode('GPS-CANARY!')
    const payload = buildRndDispatchLiteDatagram({
      msgType: 1,
      srcRadioId: 0x123456,
      dstRadioId: 0xabcdef,
      siteId: 0x0a0b0c0d,
      body: canaryGps,
    })
    const collector = new PatchCollector(payload.byteLength)
    const map = mapping()
    const result = sanitizeFromDescriptor(
      rndDispatchLiteDescriptor,
      payload,
      0,
      payload.byteLength,
      collector,
      map,
    )
    expect(result).not.toBeNull()
    collector.resolveDeferred({ mapping: map, fingerprints: new FingerprintSession() })
    const out = payload.slice()
    for (const p of collector.getPatches()) {
      out.set(p.data, p.offset)
    }
    const text = new TextDecoder().decode(out)
    expect(text).not.toContain('GPS-CANARY')
    // radio ids remapped
    const srcOut = (out[8]! << 16) | (out[9]! << 8) | out[10]!
    expect(srcOut).not.toBe(0x123456)
    expect(srcOut).not.toBe(0)
    // framing magic preserved
    expect(String.fromCharCode(out[0]!, out[1]!, out[2]!, out[3]!)).toBe('RND1')
  })
})
