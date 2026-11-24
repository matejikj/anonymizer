/**
 * T59 — NAS EPS/5GS canaries (IMSI, auth vectors, ciphered opaque, 5GMM).
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp, buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { encodeTbcd, TBCD_GSM } from '../../../src/pcap/protocols/application/binproto'
import { looksLikeNas, parseNasFrame } from '../../../src/pcap/protocols/nas'
import { sanitizeNas } from '../../../src/pcap/sanitize/nas'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'

function packetInput(data: Uint8Array) {
  return {
    index: 0,
    data,
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
  }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function latin1(buf: Uint8Array): string {
  return new TextDecoder('latin1').decode(buf)
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** Build Mobile Identity value for IMSI (type=1). */
function mobileIdentityImsi(digits: string): Uint8Array {
  const first = digits.charCodeAt(0) - 48
  const oddEven = digits.length % 2 === 1 ? 1 : 0
  const typeByte = ((first & 0x0f) << 4) | ((oddEven & 1) << 3) | 0x01
  const rest = encodeTbcd(digits.slice(1), Math.ceil((digits.length - 1) / 2) || 1, TBCD_GSM)!
  return concat(Uint8Array.of(typeByte), rest)
}

describe('T59 registry', () => {
  it('registers nas handler, mobile-core family, engine 2.36.1', () => {
    expect(APPLICATION_HANDLER_ORDER.map((h) => h.id)).toContain('nas')
    expect(familyForProtocol('nas-emm').familyId).toBe('mobile-core')
    expect(familyForProtocol('nas-imsi').familyId).toBe('mobile-core')
    expect(familyForProtocol('nas-5gmm').familyId).toBe('mobile-core')
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T59 EPS Attach Request', () => {
  it('maps IMSI TBCD and preserves attach-request message type', () => {
    const imsi = '420123456789012'
    const id = mobileIdentityImsi(imsi)
    const nas = concat(
      Uint8Array.of(0x07, 0x41), // plain EMM attach request
      Uint8Array.of(id.length),
      id,
    )
    expect(looksLikeNas(nas, 0, nas.length)).toBe(true)
    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 21_231, 21_231, nas)
    const mapping = new SessionMapping(undefined, { seed: 't59-attach' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('nas'))).toBe(true)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes(String.fromCharCode(0x41))).toBe(true)
    // TBCD of canary IMSI must not remain
    const raw = applyPatches(pkt, result)
    // Find payload region and ensure original digit sequence encoding changed
    expect(result.coverage.some((c) => c.protocol === 'nas-imsi')).toBe(true)
    // Original IMSI digits as ASCII must not appear (they're TBCD); check TBCD first bytes changed
    const idOff = pkt.length - nas.length + 3
    const origId = pkt.subarray(idOff, idOff + id.length)
    const newId = raw.subarray(idOff, idOff + id.length)
    expect([...newId]).not.toEqual([...origId])
  })
})

describe('T59 EPS Authentication Request', () => {
  it('masks RAND and AUTN', () => {
    const rand = new Uint8Array(16).fill(0xa5)
    rand[0] = 0x52 // canary marker
    rand[1] = 0x41
    rand[2] = 0x4e
    rand[3] = 0x44 // "RAND" ascii in vector
    const autn = new Uint8Array(16).fill(0x5a)
    autn[0] = 0x41
    autn[1] = 0x55
    autn[2] = 0x54
    autn[3] = 0x4e
    const nas = concat(
      Uint8Array.of(0x07, 0x52, 0x00),
      rand,
      Uint8Array.of(16),
      autn,
    )
    const pkt = buildEthIpTcp([192, 0, 2, 1], [192, 0, 2, 2], 40_000, 40_001, 1, nas)
    const mapping = new SessionMapping(undefined, { seed: 't59-auth' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    const out = latin1(applyPatches(pkt, result))
    expect(out.includes('RAND')).toBe(false)
    expect(out.includes('AUTN')).toBe(false)
    expect(result.issues.some((i) => i.includes('auth-vector'))).toBe(true)
  })
})

describe('T59 ciphered NAS', () => {
  it('masks ciphered payload without scanning TBCD', () => {
    const innerPlain = concat(
      Uint8Array.of(0x07, 0x41),
      Uint8Array.of(1),
      mobileIdentityImsi('420999888777666'),
    )
    // Outer: sec=2 (integrity+ciphered) | PD=7
    const nas = concat(
      Uint8Array.of(0x27),
      new Uint8Array([0x11, 0x22, 0x33, 0x44]), // MAC
      Uint8Array.of(0x01), // SQN
      innerPlain,
    )
    // Without nullCipher proof, looksLike requires known inner — still matches
    expect(looksLikeNas(nas, 0, nas.length)).toBe(true)
    const frame = parseNasFrame(nas, 0, nas.length)
    expect(frame?.security).toBe('ciphered')
    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 9999, 9999, nas)
    const mapping = new SessionMapping(undefined, { seed: 't59-cip' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'nas-ciphered')).toBe(true)
    expect(result.issues.some((i) => i.includes('ciphered'))).toBe(true)
    // IMSI must not be structured-mapped from ciphertext
    expect(result.coverage.some((c) => c.protocol === 'nas-imsi')).toBe(false)
  })
})

describe('T59 5GMM Registration Request', () => {
  it('maps 5GS mobile identity IMSI and preserves registration-request', () => {
    const imsi = '420111222333444'
    const id = mobileIdentityImsi(imsi)
    const nas = concat(
      Uint8Array.of(0x7e, 0x00, 0x41), // 5GMM plain registration request
      Uint8Array.of(id.length),
      id,
    )
    expect(looksLikeNas(nas, 0, nas.length)).toBe(true)
    const mapping = new SessionMapping(undefined, { seed: 't59-reg' })
    const collector = new PatchCollector(nas.length)
    const direct = sanitizeNas(nas, 0, nas.length, collector, mapping, undefined, 0)
    expect(direct?.coverage.some((c) => c.protocol === 'nas-5gmm')).toBe(true)
    expect(direct?.coverage.some((c) => c.protocol === 'nas-imsi')).toBe(true)

    // Port 50000 overlaps MOTOTRBO hints — strong NAS probe must win (engine order).
    const pkt = buildEthIpUdp([192, 0, 2, 10], [192, 0, 2, 20], 50_000, 50_000, nas)
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('nas'))).toBe(true)
  })
})

describe('T59 TAI list IE', () => {
  it('masks TAI list optional IE', () => {
    const imsi = '420123456789012'
    const id = mobileIdentityImsi(imsi)
    const tai = new Uint8Array([0x42, 0xf0, 0x70, 0x12, 0x34]) // PLMN+TAC canary shape
    const nas = concat(
      Uint8Array.of(0x07, 0x42), // attach accept
      Uint8Array.of(0x54, tai.length), // TAI list IEI
      tai,
      // also include EPS mobile identity GUTI-like as IEI 0x50
      Uint8Array.of(0x50, id.length),
      id,
    )
    // attach accept may not have mandatory LV identity — optional walk handles TAI
    const pkt = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 1111, 1111, nas)
    const mapping = new SessionMapping(undefined, { seed: 't59-tai' })
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)
    expect(result.issues.some((i) => i.includes('location'))).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'nas-location')).toBe(true)
  })
})
