/**
 * T16 — binary protocol toolkit: TLV/BER/TBCD/UTF-16/NTLMSSP + IMSI/IMEI mapping.
 */
import { describe, expect, it } from 'vitest'
import {
  SoftCursor,
  walkTlv,
  walkBer,
  readAsn1LengthCompat,
  decodeTbcd,
  encodeTbcd,
  remapTbcdBytes,
  normalizeImsiDigits,
  normalizeImeiDigits,
  imeiLuhnCheckDigit,
  isValidImeiLuhn,
  scopeImsiWithPlmn,
  IMSI_PLMN_SCOPE_SEP,
  TBCD_GSM,
  computeFixedLengthUtf16Bytes,
  decodeUtf16,
  looksLikeNtlmssp,
  parseNtlmssp,
  sanitizeNtlmssp,
} from '../../../src/pcap/protocols/application/binproto'
import { canonicalizeIdentity } from '../../../src/mapping/canonicalize'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { assertMappingDomainsComplete } from '../../../src/pcap/anonymization/mappingDomainRegistry'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { RECOVERY_CATEGORY_IDS, toRecoveryLookupCategory } from '../../../src/pcap/recovery/codec/categoryIds'
import { createTestSessionMapping } from '../../../src/pcap/anonymization'

describe('T16 SoftCursor / TLV', () => {
  it('SoftCursor never throws on OOB', () => {
    const buf = new Uint8Array([1, 2, 3])
    const cur = new SoftCursor(buf, 1, 3)
    expect(cur.u8()).toBe(2)
    expect(cur.u16(true)).toBeNull()
    expect(cur.issue?.code).toBe('u16-oob')
    expect(() => cur.slice(10)).not.toThrow()
    expect(cur.slice(10)).toBeNull()
  })

  it('walkTlv parses type-length-value and reports truncated headers', () => {
    // type=1 len=2 value=aa bb; type=2 len=0
    const buf = new Uint8Array([0x01, 0x02, 0xaa, 0xbb, 0x02, 0x00])
    const ok = walkTlv(buf, 0, buf.length, { typeWidth: 1, lengthWidth: 1, endian: 'be' })
    expect(ok.elements).toHaveLength(2)
    expect(ok.elements[0]!.type).toBe(1)
    expect(ok.elements[0]!.valueLength).toBe(2)
    expect(ok.issues).toHaveLength(0)

    const truncated = walkTlv(new Uint8Array([0x01]), 0, 1)
    expect(truncated.elements).toHaveLength(0)
    expect(truncated.issues.some((i) => i.code === 'tlv-truncated-header')).toBe(true)
  })
})

describe('T16 BER', () => {
  it('walks constructed SEQUENCE and shares length helper with TLS path', () => {
    // SEQUENCE { INTEGER 1 }  → 30 03 02 01 01
    const der = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])
    const { roots, issues } = walkBer(der, 0, der.length)
    expect(issues).toHaveLength(0)
    expect(roots).toHaveLength(1)
    expect(roots[0]!.tag.constructed).toBe(true)
    expect(roots[0]!.children).toHaveLength(1)
    expect(roots[0]!.children[0]!.tag.number).toBe(2)
    expect(readAsn1LengthCompat(der, 1, der.length)).toEqual({ length: 3, contentOffset: 2 })
  })

  it('rejects indefinite length when not allowed', () => {
    const indef = new Uint8Array([0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00])
    const { roots, issues } = walkBer(indef, 0, indef.length, { allowIndefinite: false })
    expect(roots).toHaveLength(0)
    expect(issues.some((i) => i.code === 'ber-length')).toBe(true)
  })
})

describe('T16 TBCD + phone correlation', () => {
  it('round-trips TBCD and remaps with same digit length', () => {
    const digits = '420777123456'
    const enc = encodeTbcd(digits, 8, TBCD_GSM)!
    expect(decodeTbcd(enc, TBCD_GSM)).toBe(digits)
    const mapped = '420111222333'
    const remapped = remapTbcdBytes(enc, mapped, TBCD_GSM)!
    expect(remapped.length).toBe(enc.length)
    expect(decodeTbcd(remapped, TBCD_GSM)).toBe(mapped)
  })

  it('SIP phone alias matches TBCD remapped digits via shared sip-phone mapping', () => {
    const mapping = createTestSessionMapping('t16-phone')
    const phone = '+420777123456'
    const canon = canonicalizeIdentity('sip-phone', phone)!
    const alias = mapping.map('sip-phone', canon)
    const digits = canon.replace(/\D/g, '')
    const aliasDigits = alias.replace(/\D/g, '')
    expect(aliasDigits.length).toBe(digits.length)
    const tbcd = encodeTbcd(digits, 8, TBCD_GSM)!
    const remapped = remapTbcdBytes(tbcd, aliasDigits, TBCD_GSM)!
    expect(decodeTbcd(remapped, TBCD_GSM)).toBe(aliasDigits)
  })
})

describe('T16 IMSI / IMEI categories', () => {
  it('canonicalizes and maps length-stable distinct aliases', () => {
    assertMappingDomainsComplete()
    const imsi = normalizeImsiDigits('230011234567890')!
    const imei = normalizeImeiDigits('356938035643809')!
    expect(canonicalizeIdentity('imsi', imsi)).toBe(imsi)
    expect(canonicalizeIdentity('imei', imei)).toBe(imei)
    const mapping = createTestSessionMapping('t16-imsi')
    const a = mapping.map('imsi', imsi)
    const b = mapping.map('imei', imei)
    expect(a).toHaveLength(imsi.length)
    expect(b).toHaveLength(imei.length)
    expect(a).not.toBe(imsi)
    expect(b).not.toBe(imei)
    expect(/^\d+$/.test(a)).toBe(true)
    expect(mapping.map('imsi', imsi)).toBe(a)
    expect(toRecoveryLookupCategory('imsi')).toBe('imsi')
    expect(RECOVERY_CATEGORY_IDS.imsi).toBe(20)
    expect(RECOVERY_CATEGORY_IDS.imei).toBe(21)
  })

  it('preserves MCC+MNC when PLMN scope is explicit; map-all remaps whole IMSI', () => {
    const scoped = scopeImsiWithPlmn('230011234567890', 2)!
    expect(scoped).toBe(`23001${IMSI_PLMN_SCOPE_SEP}1234567890`)
    expect(canonicalizeIdentity('imsi', scoped)).toBe(scoped)
    // Default test mapping inherits preserve-plmn from DEFAULT_MAPPING_CONFIG
    const mapping = createTestSessionMapping('t16-imsi-plmn')
    const alias = mapping.map('imsi', scoped)
    expect(alias.startsWith('23001')).toBe(true)
    expect(alias.slice(5)).not.toBe('1234567890')
    expect(alias).toHaveLength(15)
    expect(alias).not.toContain(IMSI_PLMN_SCOPE_SEP)

    const hp = new SessionMapping(
      {
        ip: 'privacy-preserving',
        mac: 'locally-administered',
        timestamps: 'enumerated',
        ephemeralPorts: 'permute',
        contentSignalingPorts: 'permute',
        vlan: 'map',
        imsiPlmn: 'map-all',
      },
      { seed: 't16-imsi-mapall' },
    )
    const hpAlias = hp.map('imsi', scoped)
    expect(hpAlias.startsWith('23001')).toBe(false)
    expect(hpAlias).toHaveLength(15)
  })

  it('15-digit IMEI aliases pass Luhn; IMEISV stays length-stable without Luhn', () => {
    expect(isValidImeiLuhn('356938035643809')).toBe(true)
    expect(imeiLuhnCheckDigit('35693803564380')).toBe(9)
    const mapping = createTestSessionMapping('t16-imei-luhn')
    for (let i = 0; i < 20; i++) {
      const body = `35693803${String(100000 + i).slice(0, 6)}`
      const check = imeiLuhnCheckDigit(body)!
      const imei = `${body}${check}`
      const alias = mapping.map('imei', imei)
      expect(alias).toHaveLength(15)
      expect(alias).not.toBe(imei)
      expect(isValidImeiLuhn(alias)).toBe(true)
    }
    const imeisv = '3569380356438090'
    const svAlias = mapping.map('imei', imeisv)
    expect(svAlias).toHaveLength(16)
    expect(svAlias).not.toBe(imeisv)
    expect(/^\d{16}$/.test(svAlias)).toBe(true)
  })
})

describe('T16 UTF-16', () => {
  it('pads and rejects surrogates', () => {
    const bytes = computeFixedLengthUtf16Bytes(10, 'AB', 'le')
    expect(bytes.length).toBe(10)
    expect(decodeUtf16(bytes, 'le')).toBe('AB   ')
    expect(() => computeFixedLengthUtf16Bytes(4, '\uD800', 'le')).toThrow()
  })
})

describe('T16 NTLMSSP', () => {
  it('parses Type 1 signature and masks on sanitize without throw', () => {
    // Minimal Type 1: signature + type + flags + empty domain/workstation buffers
    const msg = new Uint8Array(32)
    msg.set([0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00], 0)
    msg[8] = 1 // type
    expect(looksLikeNtlmssp(msg)).toBe(true)
    const parsed = parseNtlmssp(msg, 0, msg.length)
    expect(parsed?.messageType).toBe(1)
    const collector = new PatchCollector(msg.length)
    const mapping = new SessionMapping({}, { seed: 't16-ntlm' })
    expect(
      sanitizeNtlmssp(msg, 0, msg.length, collector, mapping, undefined, 0),
    ).toBe(true)
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
  })

  it('rejects security buffer pointing into header', () => {
    const msg = new Uint8Array(40)
    msg.set([0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00], 0)
    msg[8] = 1
    // domain buffer: length=4, offset=4 (inside header)
    msg[16] = 4
    msg[17] = 0
    msg[18] = 4
    msg[19] = 0
    msg[20] = 4
    msg[21] = 0
    msg[22] = 0
    msg[23] = 0
    const parsed = parseNtlmssp(msg, 0, msg.length)
    expect(parsed?.issues.some((i) => i.includes('oob') || i.includes('buffer'))).toBe(true)
  })
})

describe('T16 engine version', () => {
  it('bumps PCAP_ENGINE_VERSION for binary toolkit + IMSI/IMEI', () => {
    expect(PCAP_ENGINE_VERSION).toBe('2.35.0')
  })
})
