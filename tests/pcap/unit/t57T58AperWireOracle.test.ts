/**
 * Independent APER wire oracles for pinned S1AP/NGAP IE shapes (not encode→decode roundtrip).
 */
import { describe, expect, it } from 'vitest'
import { decodeAper, encodeAper } from '../../../src/pcap/protocols/asn1/aper'
import {
  ENB_UE_S1AP_ID_TYPE,
  MME_UE_S1AP_ID_TYPE,
  EUTRAN_CGI_TYPE,
  GUMMEI_TYPE,
} from '../../../src/pcap/protocols/asn1/aper/s1apSchema.ts'
import {
  AMF_UE_NGAP_ID_TYPE,
  RAN_UE_NGAP_ID_TYPE,
  UL_NGU_UP_TNL_TYPE,
} from '../../../src/pcap/protocols/asn1/aper/ngapSchema.ts'

describe('T57 pinned IE wire oracles', () => {
  it('ENB-UE-S1AP-ID 0x1234 wire 40 12 34 decodes independently to 4660', () => {
    const wire = Uint8Array.from([0x40, 0x12, 0x34])
    const dec = decodeAper(wire, 0, wire.length, ENB_UE_S1AP_ID_TYPE)
    expect(dec.ok).toBe(true)
    expect(dec.leaves[0]?.value).toBe(0x1234)
    const enc = encodeAper(ENB_UE_S1AP_ID_TYPE, 0x1234)
    expect(Array.from(enc!)).toEqual([0x40, 0x12, 0x34])
  })

  it('MME-UE-S1AP-ID 99 encodes to two-octet aligned field 0x00 0x63', () => {
    const wire = encodeAper(MME_UE_S1AP_ID_TYPE, 99)
    expect(wire).not.toBeNull()
    expect(Array.from(wire!)).toEqual([0x00, 0x63])
  })

  it('E-UTRAN-CGI pinned shape encodes PLMN + 28-bit cellIdentity prefix', () => {
    const plmn = new Uint8Array([0x02, 0xf8, 0x39])
    const wire = encodeAper(EUTRAN_CGI_TYPE, {
      pLMNidentity: plmn,
      cellIdentity: 0x0a1b2c0,
    })
    expect(wire).not.toBeNull()
    expect(wire!.length).toBeGreaterThanOrEqual(4)
    expect(Array.from(wire!.subarray(0, 3))).toEqual([0x02, 0xf8, 0x39])
  })

  it('GUMMEI pinned shape preserves PLMN octets on the wire', () => {
    const plmn = new Uint8Array([0x02, 0xf8, 0x39])
    const wire = encodeAper(GUMMEI_TYPE, {
      pLMNidentity: plmn,
      mMEGroupID: new Uint8Array([0x12, 0x34]),
      mMECode: new Uint8Array([0x56]),
    })
    expect(wire).not.toBeNull()
    expect(Array.from(wire!.subarray(0, 3))).toEqual([0x02, 0xf8, 0x39])
  })
})

describe('T58 pinned IE wire oracles', () => {
  it('AMF-UE-NGAP-ID 1 encodes to X.691 indefinite-range wire 00 01', () => {
    const wire = encodeAper(AMF_UE_NGAP_ID_TYPE, 1)
    expect(wire).not.toBeNull()
    expect(Array.from(wire!)).toEqual([0x00, 0x01])
  })

  it('RAN-UE-NGAP-ID 0x2345 wire 40 23 45 decodes independently to 9029', () => {
    const wire = Uint8Array.from([0x40, 0x23, 0x45])
    const dec = decodeAper(wire, 0, wire.length, RAN_UE_NGAP_ID_TYPE)
    expect(dec.ok).toBe(true)
    expect(dec.leaves[0]?.value).toBe(0x2345)
    const enc = encodeAper(RAN_UE_NGAP_ID_TYPE, 0x2345)
    expect(Array.from(enc!)).toEqual([0x40, 0x23, 0x45])
  })

  it('UL-NGU-UP-TNL pinned IPv4+TEID encodes TEID at fixed tail offset', () => {
    const teid = new Uint8Array([0x0a, 0x1b, 0x2c, 0x3d])
    const wire = encodeAper(UL_NGU_UP_TNL_TYPE, {
      transportLayerAddress: 0x0a010203,
      gtpTeid: teid,
    })
    expect(wire).not.toBeNull()
    expect(Array.from(wire!.slice(-4))).toEqual([0x0a, 0x1b, 0x2c, 0x3d])
  })
})
