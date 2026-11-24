/**
 * T23 — LDAP / Kerberos: passwords & enc-part masked; DN structure; resultCode preserved.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp, buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { UNSUPPORTED_PROTOCOL_NAMES } from '../../../src/pcap/sanitize/unsupportedIdentification'
import { looksLikeNtlmssp, sanitizeNtlmssp } from '../../../src/pcap/protocols/application/binproto'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'

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

function berLen(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n])
  if (n < 0x100) return new Uint8Array([0x81, n])
  return new Uint8Array([0x82, (n >> 8) & 0xff, n & 0xff])
}

function ber(tag: number, content: Uint8Array): Uint8Array {
  const len = berLen(content.length)
  const out = new Uint8Array(1 + len.length + content.length)
  out[0] = tag
  out.set(len, 1)
  out.set(content, 1 + len.length)
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((a, p) => a + p.length, 0)
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function octet(s: string): Uint8Array {
  return ber(0x04, new TextEncoder().encode(s))
}

function integer(n: number): Uint8Array {
  if (n < 0x80) return ber(0x02, new Uint8Array([n]))
  return ber(0x02, new Uint8Array([(n >> 8) & 0xff, n & 0xff]))
}

function enumerated(n: number): Uint8Array {
  return ber(0x0a, new Uint8Array([n]))
}

function ctx(tag: number, content: Uint8Array, constructed = true): Uint8Array {
  return ber((constructed ? 0xa0 : 0x80) | (tag & 0x1f), content)
}

function app(tag: number, content: Uint8Array): Uint8Array {
  return ber(0x60 | (tag & 0x1f), content)
}

function seq(...children: Uint8Array[]): Uint8Array {
  return ber(0x30, concat(...children))
}

describe('T23 registry', () => {
  it('registers ldap/kerberos and directory family', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('ldap')
    expect(ids).toContain('kerberos')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('ldap')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('kerberos')
    expect(familyForProtocol('ldap').familyId).toBe('directory')
    expect(familyForProtocol('kerberos').familyId).toBe('directory')
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T23 LDAP', () => {
  it('masks bind password and maps DN CN while preserving resultCode shape', () => {
    const dn = 'CN=Alice Canary,OU=Users,DC=example,DC=com'
    const password = 'LDAP-SECRET-99'
    const bindReq = app(
      0,
      concat(
        integer(3), // version
        octet(dn),
        ctx(0, new TextEncoder().encode(password), false), // simple auth
      ),
    )
    const bindMsg = seq(integer(1), bindReq)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 12345, 389, 1, bindMsg)
    const mapping = new SessionMapping(undefined, { seed: 't23-ldap' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ldap')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('LDAP-SECRET-99')).toBe(false)
    expect(text.includes('Alice Canary')).toBe(false)
    expect(text.includes('CN=')).toBe(true)
    expect(text.includes('DC=')).toBe(true)
  })

  it('preserves LDAP resultCode in bindResponse', () => {
    const bindRsp = app(
      1,
      concat(
        enumerated(49), // invalidCredentials
        octet(''),
        octet(''),
      ),
    )
    const msg = seq(integer(2), bindRsp)
    const frame = buildEthIpTcp([10, 0, 0, 2], [10, 0, 0, 1], 389, 12345, 1, msg)
    const mapping = new SessionMapping(undefined, { seed: 't23-rc' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    const out = applyPatches(frame, result)
    // ENUMERATED 49 must remain
    expect(out.includes(49)).toBe(true)
  })
})

describe('T23 Kerberos', () => {
  it('masks EncryptedData cipher canary and keeps etype', () => {
    const cipher = new TextEncoder().encode('KRB-ENC-CANARY!!!!') // 18 bytes
    const encRaw = seq(integer(18), ber(0x04, cipher))
    const body = seq(integer(5), integer(11), encRaw)
    const asRep = ber(0x6b, body) // APPLICATION 11
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 88, 88, asRep)
    const mapping = new SessionMapping(undefined, { seed: 't23-krb' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'kerberos')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('KRB-ENC-CANARY')).toBe(false)
    expect(out.includes(18)).toBe(true)
  })
})

describe('T23 NTLMSSP consistency', () => {
  it('maps user-id via T16 sanitizer (shared with LDAP SASL path)', () => {
    // Minimal NTLM Type 3 with user "alice" UTF-16LE
    const sig = new TextEncoder().encode('NTLMSSP\0')
    const user = new Uint8Array([0x61, 0x00, 0x6c, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00]) // alice
    const hdr = new Uint8Array(64)
    hdr.set(sig, 0)
    hdr[8] = 3 // type
    // lm response empty at 12
    // nt response empty at 20
    // domain empty at 28
    // user buf at 36: len=10, maxlen=10, offset=64
    hdr[36] = 10
    hdr[37] = 0
    hdr[38] = 10
    hdr[39] = 0
    hdr[40] = 64
    hdr[41] = 0
    hdr[42] = 0
    hdr[43] = 0
    const msg = concat(hdr, user)
    expect(looksLikeNtlmssp(msg, 0, msg.length)).toBe(true)
    const mapping = new SessionMapping(undefined, { seed: 't23-ntlm' })
    const collector = new PatchCollector(msg.length)
    sanitizeNtlmssp(msg, 0, msg.length, collector, mapping, undefined, 0)
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
    const out = msg.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)
    expect([...out.subarray(64, 74)]).not.toEqual([...user])
  })
})
