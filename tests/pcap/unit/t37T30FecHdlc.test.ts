/**
 * T37 — T.38 IFP honest limits: ASCII TSI map; HDLC/PER/FEC → mask-only with issues.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { sanitizeT38Udptl } from '../../../src/pcap/sanitize/t38'

function apply(collector: PatchCollector, buf: Uint8Array, mapping: SessionMapping): Uint8Array {
  collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
  const out = buf.slice()
  for (const p of collector.getPatches()) out.set(p.data, p.offset)
  return out
}

describe('T37 T.30 HDLC / FEC mask-only', () => {
  it('masks HDLC-framed binary TSI (no ASCII map) with t30-hdlc-mask-only', () => {
    const hdlcPayload = new Uint8Array([
      0xff, 0xff, 0x03, 0x80, 0x42, 0x07, 0x77, 0x12, 0x34, 0x56, 0x00, 0x00, 0xff,
    ])
    const udptl = new Uint8Array(2 + hdlcPayload.length)
    udptl[0] = 0x00
    udptl[1] = 0x02
    udptl.set(hdlcPayload, 2)

    const mapping = new SessionMapping(undefined, { seed: 't37-hdlc' })
    const collector = new PatchCollector(udptl.length)
    const r = sanitizeT38Udptl(udptl, 0, udptl.length, collector, mapping, undefined, 0)
    expect(r?.issues).toContain('t30-hdlc-mask-only')
    expect(r?.issues).not.toContain('t30-tsi-ascii-mapped')
    const out = apply(collector, udptl, mapping)
    expect([...out.subarray(2, 2 + hdlcPayload.length)]).not.toEqual([...hdlcPayload])
  })

  it('masks page canary present only in trailing FEC/redundancy copy bytes', () => {
    const canary = new TextEncoder().encode('PAGE-CANARY-ONLY-IN-FEC')
    const udptl = new Uint8Array(2 + 4 + canary.length)
    udptl[0] = 0x00
    udptl[1] = 0x03
    udptl[2] = 0x00
    udptl[3] = 0x01
    udptl[4] = 0x00
    udptl[5] = 0x00
    udptl.set(canary, 6)

    const mapping = new SessionMapping(undefined, { seed: 't37-fec' })
    const collector = new PatchCollector(udptl.length)
    const r = sanitizeT38Udptl(udptl, 0, udptl.length, collector, mapping, undefined, 0)
    expect(r?.issues).toContain('t30-per-fec-mask-only')
    const out = apply(collector, udptl, mapping)
    expect(new TextDecoder('latin1').decode(out).includes('PAGE-CANARY-ONLY-IN-FEC')).toBe(false)
    expect(out[0]).toBe(0x00)
    expect(out[1]).toBe(0x03)
  })
})
