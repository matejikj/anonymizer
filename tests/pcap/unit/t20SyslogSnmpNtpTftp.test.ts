/**
 * T20 — Syslog / SNMP / NTP / TFTP structured sanitizers.
 */
import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp, envelope } from '../fixtures/voipCorpus'
import { runDiagnosticExportPipeline } from '../helpers/diagnosticPipeline'
import { PCAP_ENGINE_VERSION } from '../../../src/pcap/export/planSnapshot'
import { APPLICATION_HANDLER_ORDER } from '../../../src/pcap/kernel/applicationHandlers'
import { familyForProtocol } from '../../../src/pcap/coverage/protocolFamilies'
import { UNSUPPORTED_PROTOCOL_NAMES } from '../../../src/pcap/sanitize/unsupportedIdentification'
import { createPayloadTimeSession } from '../../../src/pcap/kernel/payloadTimeCodec'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { sanitizeSyslog } from '../../../src/pcap/sanitize/syslog'
import { sanitizeSnmp } from '../../../src/pcap/sanitize/snmp'
import { sanitizeNtp } from '../../../src/pcap/sanitize/ntp'
import { sanitizeTftp } from '../../../src/pcap/sanitize/tftp'

function packetInput(data: Uint8Array, index = 0) {
  return {
    index,
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

describe('T20 registry / families', () => {
  it('registers handlers and promotes families off unsupported', () => {
    const ids = APPLICATION_HANDLER_ORDER.map((h) => h.id)
    expect(ids).toContain('syslog')
    expect(ids).toContain('snmp')
    expect(ids).toContain('ntp')
    expect(ids).toContain('tftp')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('snmp')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('syslog')
    expect(UNSUPPORTED_PROTOCOL_NAMES).not.toContain('ntp')
    expect(familyForProtocol('syslog').familyId).toBe('logging')
    expect(familyForProtocol('snmp').familyId).toBe('management')
    expect(familyForProtocol('ntp').familyId).toBe('management')
    expect(familyForProtocol('tftp').familyId).toBe('management')
    expect(PCAP_ENGINE_VERSION).toBe('2.44.0')
  })
})

describe('T20 syslog', () => {
  it('maps hostname and removes canary IPv4 from MSG in diagnostic', () => {
    const msg = ascii('<14>Jan  1 12:00:00 host-canary app: peer 203.0.113.77\n')
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 514, 514, msg)
    const mapping = new SessionMapping(undefined, { seed: 't20-syslog' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'syslog')).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('latin1').decode(out)
    expect(text.includes('host-canary')).toBe(false)
    expect(text.includes('203.0.113.77')).toBe(false)
  })

  it('masks free MSG text itself and keeps a structurally handled header', () => {
    // A user name the text detectors cannot recognise (e.g. one also seen in SIP signaling).
    const msg = ascii('<134>Nov 20 10:00:00 rgw-01 radio[42]: call from dispatcherjana ended\n')
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 40514, 514, msg)
    const msgStart = 14 + 20 + 8 + '<134>Nov 20 10:00:00 rgw-01 '.length
    for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
      // Handler level: the masking must not depend on the export boundary (reassembly overlays skip it).
      const handlerOut = syslogHandlerOutput(msg, policy)
      expect(handlerOut.includes('dispatcherjana')).toBe(false)
      expect(handlerOut.startsWith('<134>')).toBe(true)

      const result = sanitizePacket(packetInput(frame), policy, new SessionMapping(undefined, { seed: 't20-syslog-msg' }))
      const syslog = result.coverage.filter((c) => c.protocol === 'syslog')
      // T69 — MSG free-text may report covered (map/pseudonym) instead of blank redacted.
      const msgStatus = syslog.find((c) => c.offset === msgStart)?.status
      expect(['redacted', 'covered']).toContain(msgStatus)
      expect(syslog.some((c) => c.status === 'covered' && c.offset === 14 + 20 + 8)).toBe(true)
      expect(syslog.some((c) => c.status === 'heuristic')).toBe(false)
    }

    const { built } = runDiagnosticExportPipeline([envelope(frame)], 'syslog-msg.pcap', 't20-syslog-msg', {
      mappingSeed: 't20-syslog-msg',
    })
    const exported = new Uint8Array(built.buffer)
    expect(new TextDecoder('latin1').decode(exported).includes('dispatcherjana')).toBe(false)
    // Header survives for diagnostics: PRI kept, hostname mapped (same length, different text).
    const exportedPayload = exported.subarray(24 + 16 + 14 + 20 + 8)
    const header = new TextDecoder('latin1').decode(exportedPayload.subarray(0, msgStart - 42))
    expect(header.startsWith('<134>')).toBe(true)
    expect(header.length).toBe('<134>Nov 20 10:00:00 rgw-01 '.length)
    // A 3164 timestamp without year may be masked (documented); the hostname is a same-length alias.
    const hostname = header.slice('<134>Nov 20 10:00:00 '.length, -1)
    expect(hostname).not.toBe('rgw-01')
    expect(/^[A-Za-z0-9.-]{6}$/.test(hostname)).toBe(true)
  })

  it('RFC 5424: masks unmapped STRUCTURED-DATA values, maps ip/host', () => {
    const msg = ascii('<14>1 2026-11-20T10:00:00Z rgw-01 app 42 ID7 [exampleSDID@32473 user="jana.novakova" ip="10.1.2.3" note="a \\"quoted\\" secret"] hello\n')
    for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
      const out = syslogHandlerOutput(msg, policy)
      expect(out.includes('jana.novakova')).toBe(false)
      expect(out.includes('10.1.2.3')).toBe(false)
      expect(out.includes('secret')).toBe(false)
      expect(out.includes('exampleSDID@32473')).toBe(true)
      expect(out.includes(' user="')).toBe(true)
    }
  })

  it.each([
    ['unquoted value', '[meta user=jana.novakova]'],
    ['stray text between params', '[x@32473 a="1" jana.novakova b="2"]'],
    ['text-only element', '[meta jana.novakova]'],
  ])('RFC 5424: masks a non-conforming SD block as a whole (%s)', (_label, sd) => {
    const msg = ascii(`<14>1 2026-11-20T10:00:00Z rgw-01 app 42 ID7 ${sd} hi\n`)
    for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
      expect(syslogHandlerOutput(msg, policy).includes('jana.novakova')).toBe(false)
    }
  })

  it('RFC 5424: a header with fewer than five fields is not exported unparsed', () => {
    const msg = ascii('<14>1 2026-11-20T10:00:00Z secret-host9 app')
    for (const policy of [DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY]) {
      expect(syslogHandlerOutput(msg, policy).includes('secret-host9')).toBe(false)
    }
  })
})

/** Syslog handler output alone (no export boundary), as latin1 text. */
function syslogHandlerOutput(payload: Uint8Array, policy: typeof DIAGNOSTIC_POLICY): string {
  const mapping = new SessionMapping(undefined, { seed: 't20-syslog-handler' })
  const pt = createPayloadTimeSession('relative', 't20-syslog-handler')
  pt.bindCaptureReference({ ticks: 1_763_632_800_000n, unitsPerSecond: 1000n, offsetSeconds: 0n })
  const collector = new PatchCollector(payload.length)
  expect(sanitizeSyslog(payload, 0, payload.length, collector, mapping, undefined, 0, policy, pt)).not.toBeNull()
  collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
  const out = payload.slice()
  for (const p of collector.getPatches()) out.set(p.data, p.offset)
  return new TextDecoder('latin1').decode(out)
}

describe('T20 SNMP', () => {
  it('masks community string in v2c GetRequest', () => {
    // SEQUENCE { INTEGER 1, OCTET STRING "public", GetRequest-PDU … minimal }
    // SEQUENCE { version=1, community="public", GetRequest-PDU {…, varbind-list empty} }
    const pdu = new Uint8Array([
      0x30, 0x18,
      0x02, 0x01, 0x01, // version 1 (v2c)
      0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // "public"
      0xa0, 0x0b, // get-request len=11
      0x02, 0x01, 0x01,
      0x02, 0x01, 0x00,
      0x02, 0x01, 0x00,
      0x30, 0x00,
    ])
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 161, 161, pdu)
    const mapping = new SessionMapping(undefined, { seed: 't20-snmp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'snmp' && c.status === 'covered')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('public')).toBe(false)
  })
})

describe('T20 NTP', () => {
  it('maps IPv4 refid and does not leave original address bytes', () => {
    const ntp = new Uint8Array(48)
    ntp[0] = 0x1c // vn=3 mode=4
    ntp[1] = 2 // stratum 2
    // refid 10.1.2.3
    ntp[12] = 10
    ntp[13] = 1
    ntp[14] = 2
    ntp[15] = 3
    // non-zero transmit timestamp
    ntp[40] = 0xe5
    ntp[41] = 0x00
    ntp[42] = 0x00
    ntp[43] = 0x01
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 123, 123, ntp)
    const mapping = new SessionMapping(undefined, { seed: 't20-ntp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'ntp')).toBe(true)
    const out = applyPatches(frame, result)
    const payloadOff = 14 + 20 + 8
    // Topology-preserving map may keep 10/8; require the full refid to change.
    expect([
      out[payloadOff + 12],
      out[payloadOff + 13],
      out[payloadOff + 14],
      out[payloadOff + 15],
    ]).not.toEqual([10, 1, 2, 3])
  })
})

describe('T20 TFTP', () => {
  it('masks DATA payload and maps RRQ filename', () => {
    const rrq = new Uint8Array([
      0x00, 0x01,
      ...ascii('secret-config.cfg'),
      0x00,
      ...ascii('octet'),
      0x00,
    ])
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 69, 12_000, rrq)
    const mapping = new SessionMapping(undefined, { seed: 't20-tftp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'tftp')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes('secret-config.cfg')).toBe(false)

    const dataPkt = new Uint8Array([0x00, 0x03, 0x00, 0x01, ...ascii('PASSWORD=canary')])
    const dataFrame = buildEthIpUdp([10, 0, 0, 2], [10, 0, 0, 1], 12_000, 69, dataPkt)
    const r2 = sanitizePacket(packetInput(dataFrame), HIGH_PRIVACY_POLICY, mapping)
    const out2 = applyPatches(dataFrame, r2)
    expect(new TextDecoder('latin1').decode(out2).includes('PASSWORD=canary')).toBe(false)
  })
})

describe('T20 unit facades', () => {
  it('sanitize helpers claim on signature without throw', () => {
    const mapping = new SessionMapping(undefined, { seed: 't20-unit' })
    const pt = createPayloadTimeSession('relative', 't20-seed')
    pt.bindCaptureReference({
      ticks: 1_700_000_000_000n,
      unitsPerSecond: 1000n,
      offsetSeconds: 0n,
    })
    const syslog = ascii('<13>1 2024-01-01T00:00:00Z router - - - hello')
    const c1 = new PatchCollector(syslog.length)
    expect(
      sanitizeSyslog(syslog, 0, syslog.length, c1, mapping, undefined, 0, DIAGNOSTIC_POLICY, pt),
    ).not.toBeNull()
    const snmp = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00])
    const c2 = new PatchCollector(snmp.length)
    expect(sanitizeSnmp(snmp, 0, snmp.length, c2, mapping, undefined, 0)).not.toBeNull()
    const ntp = new Uint8Array(48)
    ntp[0] = 0x1b
    const c3 = new PatchCollector(48)
    expect(sanitizeNtp(ntp, 0, 48, c3, mapping, undefined, 0, pt)).not.toBeNull()
    const tftp = new Uint8Array([0x00, 0x01, 0x61, 0x00, 0x6f, 0x00])
    const c4 = new PatchCollector(tftp.length)
    expect(
      sanitizeTftp(tftp, 0, tftp.length, c4, mapping, undefined, 0, false, 69, 1234),
    ).not.toBeNull()
    for (const c of [c1, c2, c3, c4]) {
      c.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
    }
  })
})
