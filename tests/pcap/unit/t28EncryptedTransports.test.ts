/**
 * T28 — SSH / QUIC Initial / IKE NAT_DETECTION / WireGuard / ESP mask-first contracts.
 */
import { describe, expect, it } from 'vitest'
import type { PacketEnvelope } from '../../../src/pcap/domain/types'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp, buildEthIpTcp } from '../fixtures/voipCorpus'
import { runDiagnosticExportPipeline } from '../helpers/diagnosticPipeline'
import { looksLikeWireGuard } from '../../../src/pcap/sanitize/wireguard'
import { sanitizeQuic } from '../../../src/pcap/sanitize/quic'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { FingerprintSession } from '../../../src/pcap/anonymization/fingerprintSession'

const CANARY = 'QUIC-SNI-CANARY.example.test'

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

function buildTlsClientHelloBody(sni: string): Uint8Array {
  const sniBytes = Array.from(sni, (c) => c.charCodeAt(0))
  const serverNameEntry = [0x00, (sniBytes.length >> 8) & 0xff, sniBytes.length & 0xff, ...sniBytes]
  const serverNameList = [(serverNameEntry.length >> 8) & 0xff, serverNameEntry.length & 0xff, ...serverNameEntry]
  const serverNameExtension = [
    0x00,
    0x00,
    (serverNameList.length >> 8) & 0xff,
    serverNameList.length & 0xff,
    ...serverNameList,
  ]
  const handshakeBody = [
    0x03,
    0x03,
    ...new Array(32).fill(0),
    0x00,
    0x00,
    0x02,
    0xc0,
    0x2f,
    0x01,
    0x00,
    (serverNameExtension.length >> 8) & 0xff,
    serverNameExtension.length & 0xff,
    ...serverNameExtension,
  ]
  return new Uint8Array(handshakeBody)
}

function wrapDtlsHandshakeMessage(body: Uint8Array, messageSeq = 0): Uint8Array {
  const msgLen = body.length
  const hs = new Uint8Array(12 + msgLen)
  hs[0] = 0x01
  hs[1] = (msgLen >> 16) & 0xff
  hs[2] = (msgLen >> 8) & 0xff
  hs[3] = msgLen & 0xff
  hs[4] = (messageSeq >> 8) & 0xff
  hs[5] = messageSeq & 0xff
  hs[9] = (msgLen >> 16) & 0xff
  hs[10] = (msgLen >> 8) & 0xff
  hs[11] = msgLen & 0xff
  hs.set(body, 12)
  return hs
}

function wrapDtlsHandshakeRecord(handshakeBytes: Uint8Array): Uint8Array {
  const record = new Uint8Array(13 + handshakeBytes.length)
  record[0] = 0x16
  record[1] = 0xfe
  record[2] = 0xfd
  record[11] = (handshakeBytes.length >> 8) & 0xff
  record[12] = handshakeBytes.length & 0xff
  record.set(handshakeBytes, 13)
  return record
}

function buildOpenVpnDataDatagram(): Uint8Array {
  const pkt = new Uint8Array(1 + 8 + 4 + 8)
  pkt[0] = 6 << 3
  for (let i = 0; i < 8; i++) pkt[1 + i] = 0x11 + i
  pkt[9] = 0
  pkt[10] = 0
  pkt[11] = 0
  pkt[12] = 1
  for (let i = 0; i < 8; i++) pkt[13 + i] = 0xee
  return pkt
}

function wrapOpenVpnTcpFrame(datagram: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + datagram.length)
  out[0] = (datagram.length >> 8) & 0xff
  out[1] = datagram.length & 0xff
  out.set(datagram, 2)
  return out
}

function buildQuicInitialWithCanary(canary: string): Uint8Array {
  // Minimal QUIC v1 Initial long header + unprotected "payload" containing canary.
  // (Not a valid AEAD — T28 baseline masks the entire protected payload region.)
  const dcid = new Uint8Array([0x11, 0x22, 0x33, 0x44])
  const scid = new Uint8Array([0xaa, 0xbb])
  const token = new Uint8Array(0)
  const payload = ascii(`\0\0\0\0CRYPTO…${canary}…tail`)
  const parts: number[] = []
  parts.push(0xc0) // long header, Initial type bits for v1
  parts.push(0x00, 0x00, 0x00, 0x01) // version 1
  parts.push(dcid.length, ...dcid)
  parts.push(scid.length, ...scid)
  parts.push(0x00) // token length varint 0
  // payload length as 2-byte varint (01xxxxxx)
  const plen = payload.length
  parts.push(0x40 | ((plen >> 8) & 0x3f), plen & 0xff)
  parts.push(...payload)
  return new Uint8Array(parts)
}

describe('T28 encrypted transports', () => {
  it('SSH banner masks comment; host-key reply is redacted', () => {
    const banner = ascii('SSH-2.0-OpenSSH_9.6 canary-comment\r\n')
    // Binary KEX reply packet: length=10, pad=2, type=31, then 7 bytes body+pad
    const body = new Uint8Array([0x00, 0x00, 0x00, 0x0a, 0x02, 31, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04])
    const payload = new Uint8Array(banner.length + body.length)
    payload.set(banner, 0)
    payload.set(body, banner.length)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 22, 12345, 1, payload)
    const mapping = new SessionMapping(undefined, { seed: 't28-ssh' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol.startsWith('ssh'))).toBe(true)
    const out = applyPatches(frame, result)
    const text = new TextDecoder('ascii', { fatal: false }).decode(out)
    expect(text.includes('canary-comment')).toBe(false)
    expect(text.includes('OpenSSH_9.6')).toBe(true)
    // host key body bytes must change
    const payloadOff = 14 + 20 + 20 + banner.length + 6
    expect(out[payloadOff]).not.toBe(0xde)
  })

  it('QUIC Initial protected payload never retains canary after sanitize', () => {
    const initial = buildQuicInitialWithCanary(CANARY)
    expect(new TextDecoder().decode(initial).includes(CANARY)).toBe(true)

    const collector = new PatchCollector(initial.length)
    const mapping = new SessionMapping(undefined, { seed: 't28-quic' })
    const res = sanitizeQuic(initial, 0, initial.length, collector, mapping, undefined, 0)
    expect(res).not.toBeNull()
    expect(res!.coverage.some((c) => c.protocol === 'quic-initial' && c.status === 'redacted')).toBe(
      true,
    )
    collector.resolveDeferred({ mapping, fingerprints: new FingerprintSession() })
    const out = initial.slice()
    for (const p of collector.getPatches()) out.set(p.data, p.offset)
    expect(new TextDecoder('ascii', { fatal: false }).decode(out).includes(CANARY)).toBe(false)

    // Full packet path
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 443, 443, initial)
    const pkt = sanitizePacket(
      packetInput(frame),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't28-quic2' }),
    )
    const exported = applyPatches(frame, pkt)
    expect(new TextDecoder('ascii', { fatal: false }).decode(exported).includes(CANARY)).toBe(false)
  })

  it('IKE NAT_DETECTION notify body is masked', () => {
    // ISAKMP header + Notify payload with NAT_DETECTION_SOURCE (16388)
    const hdr = new Uint8Array(28)
    hdr[16] = 41 // next = Notify (IKEv2)
    hdr[17] = 0x20 // version 2.0
    hdr[18] = 34 // IKE_SA_INIT
    const notifyBody = new Uint8Array([
      0, // protocol
      0, // spi size
      0x40, 0x04, // 16388
      0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, // hash canary
    ])
    const plen = 4 + notifyBody.length
    const notify = new Uint8Array(plen)
    notify[0] = 0 // next
    notify[2] = (plen >> 8) & 0xff
    notify[3] = plen & 0xff
    notify.set(notifyBody, 4)
    const payload = new Uint8Array(hdr.length + notify.length)
    payload.set(hdr, 0)
    payload.set(notify, hdr.length)
    const canary = new Uint8Array([0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef])
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 500, 500, payload)
    const result = sanitizePacket(
      packetInput(frame),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't28-ike' }),
    )
    expect(result.issues?.some((i) => i.includes('nat-detection'))).toBe(true)
    const out = applyPatches(frame, result)
    const hay = out.subarray(14 + 20 + 8)
    let found = false
    for (let i = 0; i + canary.length <= hay.length; i++) {
      let ok = true
      for (let j = 0; j < canary.length; j++) if (hay[i + j] !== canary[j]) ok = false
      if (ok) found = true
    }
    expect(found).toBe(false)
  })

  it('WireGuard rejects random UDP of handshake length; accepts typed initiation', () => {
    const random = new Uint8Array(148)
    random.fill(0x5a)
    expect(looksLikeWireGuard(random, 0, 148)).toBe(false)
    const initiation = new Uint8Array(148)
    initiation[0] = 1 // type
    // reserved 1..3 already 0
    expect(looksLikeWireGuard(initiation, 0, 148)).toBe(true)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 51820, 51820, initiation)
    const result = sanitizePacket(
      packetInput(frame),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't28-wg' }),
    )
    expect(result.coverage.some((c) => c.protocol === 'wireguard-handshake')).toBe(true)
    expect(result.coverage.every((c) => c.status !== 'encrypted')).toBe(true)
  })

  it('DTLS AppData without proven confidentiality is masked and gated as gaps (T08/R02)', () => {
    const canary = 'DTLS-APP-CANARY-PLAINTEXT'
    const body = ascii(canary)
    const dtlsHdr = 13
    const record = new Uint8Array(dtlsHdr + body.length)
    record[0] = 0x17 // application data
    record[1] = 0xfe
    record[2] = 0xfd
    record[3] = 0x00 // epoch 0 — not proof of negotiated encryption
    record[4] = 0x00
    record[11] = (body.length >> 8) & 0xff
    record[12] = body.length & 0xff
    record.set(body, dtlsHdr)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 443, 443, record)
    const result = sanitizePacket(
      packetInput(frame),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't28-dtls-app' }),
    )
    const appSpan = result.coverage.find((c) => c.protocol === 'dtls-app')
    expect(appSpan?.status).toBe('unsupported')
    expect(result.coverage.every((c) => c.status !== 'encrypted')).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes(canary)).toBe(false)
  })

  it('DTLS record truncated in datagram → requires-reassembly and masks trailing bytes', () => {
    const canary = 'DTLS-TRUNC-CANARY'
    const body = ascii(canary)
    const record = new Uint8Array(13 + body.length)
    record[0] = 0x17
    record[1] = 0xfe
    record[2] = 0xfd
    // Claim length longer than available body (wire lie / truncated capture).
    record[11] = ((body.length + 8) >> 8) & 0xff
    record[12] = (body.length + 8) & 0xff
    record.set(body, 13)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 443, 443, record)
    const result = sanitizePacket(
      packetInput(frame),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't28-dtls-trunc' }),
    )
    expect(result.coverage.some((c) => c.protocol === 'dtls' && c.status === 'requires-reassembly')).toBe(
      true,
    )
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes(canary)).toBe(false)
  })

  it('DTLS ClientHello with normative 12-byte handshake header does not leak SNI canary', () => {
    const sni = 'NORM-DTLS-12B-SNI.test'
    const record = wrapDtlsHandshakeRecord(wrapDtlsHandshakeMessage(buildTlsClientHelloBody(sni)))
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 443, 443, record)
    const result = sanitizePacket(
      packetInput(frame),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't28-dtls-12b' }),
    )
    expect(result.coverage.some((c) => c.protocol === 'dtls-clienthello' && c.status === 'covered')).toBe(
      true,
    )
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes(sni)).toBe(false)
    expect(result.coverage.every((c) => c.status !== 'encrypted')).toBe(true)
  })

  it('DTLS handshake split across UDP datagrams is unsupported but masks canary bytes', () => {
    const sni = 'CROSS-DTLS-FLIGHT-SNI.test'
    const body = buildTlsClientHelloBody(sni)
    const split = Math.floor(body.length / 2)
    const frag0Len = split
    const frag1Len = body.length - split
    const frag0 = new Uint8Array(12 + frag0Len)
    frag0[0] = 0x01
    frag0[1] = (body.length >> 16) & 0xff
    frag0[2] = (body.length >> 8) & 0xff
    frag0[3] = body.length & 0xff
    frag0[9] = (frag0Len >> 16) & 0xff
    frag0[10] = (frag0Len >> 8) & 0xff
    frag0[11] = frag0Len & 0xff
    frag0.set(body.subarray(0, split), 12)
    const frag1 = new Uint8Array(12 + frag1Len)
    frag1[0] = 0x01
    frag1[1] = (body.length >> 16) & 0xff
    frag1[2] = (body.length >> 8) & 0xff
    frag1[3] = body.length & 0xff
    frag1[6] = (split >> 16) & 0xff
    frag1[7] = (split >> 8) & 0xff
    frag1[8] = split & 0xff
    frag1[9] = (frag1Len >> 16) & 0xff
    frag1[10] = (frag1Len >> 8) & 0xff
    frag1[11] = frag1Len & 0xff
    frag1.set(body.subarray(split), 12)
    for (const [idx, frag] of [frag0, frag1].entries()) {
      const record = wrapDtlsHandshakeRecord(frag)
      const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 443, 443, record)
      const result = sanitizePacket(
        packetInput(frame, idx),
        DIAGNOSTIC_POLICY,
        new SessionMapping(undefined, { seed: `t28-dtls-split-${idx}` }),
      )
      expect(
        result.coverage.some((c) => c.protocol === 'dtls-handshake-fragment' && c.status === 'requires-reassembly'),
      ).toBe(true)
      if (idx === 0) {
        expect(result.issues?.some((i) => i.includes('dtls-handshake-fragment-partial'))).toBe(true)
      } else {
        expect(result.issues?.some((i) => i.includes('dtls-cross-datagram-reassembly-unsupported'))).toBe(
          true,
        )
      }
      const out = applyPatches(frame, result)
      expect(new TextDecoder('latin1').decode(out).includes(sni)).toBe(false)
    }
  })

  it('exports DTLS ClientHello without leaking SNI canary (T28.export)', () => {
    const sni = 'T28-DTLS-EXPORT-SNI.test'
    const record = wrapDtlsHandshakeRecord(wrapDtlsHandshakeMessage(buildTlsClientHelloBody(sni)))
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 443, 443, record)
    const envelope = (data: Uint8Array, index = 0): PacketEnvelope => ({
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
    })
    const { built } = runDiagnosticExportPipeline(
      [envelope(frame)],
      't28-dtls-export.pcap',
      't28-dtls-export',
      { mappingSeed: 't28-dtls-export' },
    )
    expect(built.validationValid).toBe(true)
    const exported = built.packets[0]!.data
    expect(new TextDecoder('latin1').decode(exported).includes(sni)).toBe(false)
  })

  it('DTLS ClientHello SNI canary is redacted via TLS handshake reuse', () => {
    const sni = 'DTLS-SNI-CANARY.test'
    const chBody = ascii(
      `\x01\x00\x00\x50\x03\x03`
        + '\x00'.repeat(32)
        + '\x00'
        + `\x00\x0f\x00\x00\x0c${sni}`,
    )
    const record = new Uint8Array(13 + chBody.length)
    record[0] = 0x16
    record[1] = 0xfe
    record[2] = 0xfd
    record[11] = (chBody.length >> 8) & 0xff
    record[12] = chBody.length & 0xff
    record.set(chBody, 13)
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 443, 443, record)
    const result = sanitizePacket(
      packetInput(frame),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't28-dtls' }),
    )
    expect(result.coverage.some((c) => c.protocol.startsWith('dtls'))).toBe(true)
    const out = applyPatches(frame, result)
    expect(new TextDecoder('latin1').decode(out).includes(sni)).toBe(false)
  })

  it('OpenVPN session id is mapped; data channel is redacted (not encrypted-preserved)', () => {
    const pkt = buildOpenVpnDataDatagram()
    const frame = buildEthIpUdp([10, 0, 0, 1], [10, 0, 0, 2], 1194, 1194, pkt)
    const mapping = new SessionMapping(undefined, { seed: 't28-ovpn' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'openvpn-data' && c.status === 'redacted')).toBe(
      true,
    )
    const out = applyPatches(frame, result)
    expect(out[42]).not.toBe(0x11)
  })

  it('OpenVPN-over-TCP length framing maps session and masks data payload', () => {
    const datagram = buildOpenVpnDataDatagram()
    const tcpPayload = wrapOpenVpnTcpFrame(datagram)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 1194, 1194, 1, tcpPayload)
    const mapping = new SessionMapping(undefined, { seed: 't28-ovpn-tcp' })
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, mapping)
    expect(result.coverage.some((c) => c.protocol === 'openvpn-tcp-framing' && c.status === 'covered')).toBe(
      true,
    )
    expect(result.coverage.some((c) => c.protocol === 'openvpn-data' && c.status === 'redacted')).toBe(
      true,
    )
    const out = applyPatches(frame, result)
    const ethIpTcp = 14 + 20 + 20
    expect(out[ethIpTcp + 2]).not.toBe(0x11)
    expect(out[ethIpTcp + 2 + 12]).not.toBe(0xee)
  })

  it('OpenVPN-over-TCP incomplete frame requires reassembly and masks canary bytes', () => {
    const datagram = buildOpenVpnDataDatagram()
    const full = wrapOpenVpnTcpFrame(datagram)
    const tcpPayload = full.subarray(0, full.length - 4)
    const frame = buildEthIpTcp([10, 0, 0, 1], [10, 0, 0, 2], 1194, 1194, 1, tcpPayload)
    const result = sanitizePacket(
      packetInput(frame),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't28-ovpn-tcp-partial' }),
    )
    expect(
      result.coverage.some((c) => c.protocol === 'openvpn-tcp' && c.status === 'requires-reassembly'),
    ).toBe(true)
    expect(result.issues.some((i) => i.includes('openvpn-tcp-requires-reassembly'))).toBe(true)
    const out = applyPatches(frame, result)
    const ethIpTcp = 14 + 20 + 20
    expect(out.slice(ethIpTcp).includes(0xee)).toBe(false)
  })

  it('ESP without SA is redacted (not encrypted-preserved)', () => {
    const esp = new Uint8Array(32)
    esp[0] = 0x12
    esp[1] = 0x34
    esp[2] = 0x56
    esp[3] = 0x78
    // rest payload canary
    for (let i = 8; i < 32; i++) esp[i] = 0xee
    const total = 14 + 20 + esp.length
    const buf = new Uint8Array(total)
    buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
    buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
    buf[12] = 0x08
    buf[13] = 0x00
    buf[14] = 0x45
    buf[16] = ((20 + esp.length) >> 8) & 0xff
    buf[17] = (20 + esp.length) & 0xff
    buf[23] = 50 // ESP
    buf.set([10, 0, 0, 1], 26)
    buf.set([10, 0, 0, 2], 30)
    buf.set(esp, 34)
    const result = sanitizePacket(
      packetInput(buf),
      DIAGNOSTIC_POLICY,
      new SessionMapping(undefined, { seed: 't28-esp' }),
    )
    expect(result.coverage.some((c) => c.protocol === 'esp' && c.status === 'redacted')).toBe(true)
    expect(result.coverage.some((c) => c.status === 'encrypted')).toBe(false)
    const out = applyPatches(buf, result)
    expect(out[34 + 8]).not.toBe(0xee)
  })
})
