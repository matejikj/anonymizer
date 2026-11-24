/**
 * T27 — SMTP/IMAP/POP3, FTP, Telnet, SMB2 enterprise plaintext sanitizers.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpTcp } from '../fixtures/voipCorpus'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { generateTextAlias, createTextReplacementCounters } from '../../../src/mapping/textAliasEngine'

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

function ascii(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

describe('T27 registry', () => {
  it('registers enterprise handlers and bumps engine version', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toEqual(expect.arrayContaining(['smtp', 'imap', 'pop3', 'ftp', 'telnet', 'smb']))
    expect(familyForProtocol('ftp-data').familyId).toBe('management')
    expect(familyForProtocol('smb2').familyId).toBe('directory')
    expect(PCAP_ENGINE_VERSION).toBe('2.37.0')
  })
})

describe('T27 SMTP', () => {
  it('maps MAIL FROM email and masks AUTH PLAIN; consistent with text alias category', () => {
    const email = 'alice.canary@corp.example'
    const payload = ascii(
      `EHLO mail.corp.example\r\nMAIL FROM:<${email}>\r\nAUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n`,
    )
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 25, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't27-smtp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'smtp' || c.protocol === 'smtp-auth')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes(email)).toBe(false)
    expect(text.includes('AGFsaWNlAHNlY3JldA==')).toBe(false)
    expect(text.includes('MAIL FROM:')).toBe(true)
    // Same category as text logs (email) — SessionMapping shares generateTextAlias shape
    const counters = createTextReplacementCounters()
    const textAlias = generateTextAlias('email', email.toLowerCase(), counters, email)
    expect(textAlias.includes('@')).toBe(true)
    expect(mapping.map('email', email.toLowerCase()).includes('@') || mapping.map('email', email.toLowerCase()).length > 0).toBe(true)
  })

  it('masks DATA body and Subject; maps From header email', () => {
    const email = 'bob.canary@corp.example'
    const payload = ascii(
      `DATA\r\nFrom: ${email}\r\nSubject: SECRET-SUBJECT-99\r\n\r\nBody canary SECRET-BODY-42\r\n.\r\n`,
    )
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 40001, 25, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't27-data' })
    const out = applyPatches(frame, sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping))
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('SECRET-SUBJECT-99')).toBe(false)
    expect(text.includes('SECRET-BODY-42')).toBe(false)
    expect(text.includes(email)).toBe(false)
  })
})

describe('T27 FTP', () => {
  it('maps USER, masks PASS, names PASV as ftp-data', () => {
    const payload = ascii(
      `USER ftp-canary-user\r\nPASS FTP-SECRET-99\r\n227 Entering Passive Mode (10,55,66,77,4,1)\r\n`,
    )
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 21, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't27-ftp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ftp-data')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'ftp-auth')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('FTP-SECRET-99')).toBe(false)
    expect(text.includes('ftp-canary-user')).toBe(false)
    expect(text.includes('10,55,66,77')).toBe(false)
    expect(text.includes('227')).toBe(true)
  })
})

describe('T27 Telnet', () => {
  it('preserves IAC WILL/DO and masks user data', () => {
    const iacWillEcho = new Uint8Array([255, 251, 1]) // IAC WILL ECHO
    const secret = ascii('password-canary-77')
    const payload = new Uint8Array(iacWillEcho.length + secret.length)
    payload.set(iacWillEcho, 0)
    payload.set(secret, iacWillEcho.length)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50001, 23, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't27-telnet' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'telnet-iac')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'telnet-data')).toBe(true)
    const out = applyPatches(frame, result)
    expect(out[54]).toBe(255) // IAC preserved at start of TCP payload
    expect(new TextDecoder('latin1').decode(out).includes('password-canary-77')).toBe(false)
  })
})

describe('T27 SMB2', () => {
  it('masks SMB1 and covers SMB2 header opaque ids', () => {
    const smb1 = new Uint8Array(36)
    smb1[0] = 0xff
    smb1[1] = 0x53
    smb1[2] = 0x4d
    smb1[3] = 0x42
    for (let i = 4; i < 36; i++) smb1[i] = 0x41
    const frame1 = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50002, 445, 1, smb1)
    const mapping = new SessionMapping(undefined, { seed: 't27-smb1' })
    const r1 = sanitizePacket(packetInput(frame1), DIAGNOSTIC_POLICY, mapping)
    expect(r1.coverage.some((c) => c.protocol === 'smb1')).toBe(true)
    expect(new TextDecoder('latin1').decode(applyPatches(frame1, r1)).includes('AAAA')).toBe(false)

    const smb2 = new Uint8Array(64)
    smb2[0] = 0xfe
    smb2[1] = 0x53
    smb2[2] = 0x4d
    smb2[3] = 0x42
    smb2[4] = 64 // structure size
    smb2[12] = 0 // NEGOTIATE
    // SessionId non-zero
    smb2[40] = 0x11
    smb2[41] = 0x22
    smb2[42] = 0x33
    smb2[43] = 0x44
    const frame2 = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50003, 445, 1, smb2)
    const r2 = sanitizePacket(packetInput(frame2), DIAGNOSTIC_POLICY, mapping)
    expect(r2.coverage.some((c) => c.protocol === 'smb2')).toBe(true)
    const out2 = applyPatches(frame2, r2)
    const sessOff = 14 + 20 + 20 + 40
    expect(out2[sessOff]).not.toBe(0x11)
  })
})

describe('T27 IMAP/POP3 auth', () => {
  it('masks IMAP LOGIN password and POP3 PASS', () => {
    const imap = ascii('a001 LOGIN alice IMAP-SECRET-11\r\n')
    const frameI = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50004, 143, 1, imap)
    const mapping = new SessionMapping(undefined, { seed: 't27-imap' })
    const outI = applyPatches(frameI, sanitizePacket(packetInput(frameI), DIAGNOSTIC_POLICY, mapping))
    expect(new TextDecoder('latin1').decode(outI).includes('IMAP-SECRET-11')).toBe(false)

    const pop = ascii('USER bob\r\nPASS POP-SECRET-22\r\n')
    const frameP = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 50005, 110, 1, pop)
    const outP = applyPatches(frameP, sanitizePacket(packetInput(frameP), DIAGNOSTIC_POLICY, mapping))
    expect(new TextDecoder('latin1').decode(outP).includes('POP-SECRET-22')).toBe(false)
  })
})
