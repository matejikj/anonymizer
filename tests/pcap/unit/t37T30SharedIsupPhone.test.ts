/**
 * T37/T25 — T.30 TSI ASCII maps via sip-phone; same alias as ISUP TBCD for one number.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { sanitizeT38Udptl } from '../../../src/pcap/sanitize/t38'
import { mapTbcdSipPhoneField } from '../../../src/pcap/sanitize/isup/tbcdPhoneMap'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto/tbcd'
import { canonicalizeIdentity } from '../../../src/mapping/canonicalize'

function apply(collector: PatchCollector, buf: Uint8Array, mapping: SessionMapping): Uint8Array {
  collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
  const out = buf.slice()
  for (const p of collector.getPatches()) out.set(p.data, p.offset)
  return out
}

describe('T37 T.30 TSI shared phone with ISUP TBCD', () => {
  it('maps 20-octet T.30 TSI field and shares SessionMapping alias with ISUP TBCD', () => {
    const digits = '420777123456'
    const tsiField = new TextEncoder().encode(`${digits}        `.slice(0, 20))
    expect(tsiField.length).toBe(20)

    const udptl = new Uint8Array(2 + 2 + tsiField.length)
    udptl[0] = 0x00
    udptl[1] = 0x01
    udptl[2] = 0x06
    udptl[3] = 0x00
    udptl.set(tsiField, 4)

    const mapping = new SessionMapping(undefined, { seed: 't37-t30-isup' })
    const collector = new PatchCollector(udptl.length)
    const r = sanitizeT38Udptl(udptl, 0, udptl.length, collector, mapping, undefined, 0)
    expect(r?.issues).toContain('t30-tsi-ascii-mapped')
    const t38Out = apply(collector, udptl, mapping)
    expect(new TextDecoder('latin1').decode(t38Out).includes(digits)).toBe(false)

    const phoneCanon = canonicalizeIdentity('sip-phone', `+${digits}`)!
    const t38Alias = mapping.get('sip-phone', phoneCanon)
    expect(t38Alias).toBeTruthy()

    const tbcd = encodeTbcd(digits, 8, TBCD_GSM)!
    const tbcdBuf = new Uint8Array(tbcd.length)
    tbcdBuf.set(tbcd, 0)
    const tbcdCollector = new PatchCollector(tbcdBuf.length)
    mapTbcdSipPhoneField(tbcdBuf, 0, tbcd.length, tbcdCollector, mapping, undefined, 0, 'isup', 'isup')
    apply(tbcdCollector, tbcdBuf, mapping)
    expect(mapping.get('sip-phone', phoneCanon)).toBe(t38Alias)
  })
})
