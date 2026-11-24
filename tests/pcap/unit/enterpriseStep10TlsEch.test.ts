/**
 * Enterprise step 10 — TLS 1.2 / 1.3 / ECH explicit branches.
 */

import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import {
  DIAGNOSTIC_POLICY,
  sanitizePacket,
  type PacketInput,
  summarizeTlsHandling,
  findReadableCertIdentities,
  sanitizeTls,
  PatchCollector,
} from '../../../src/pcap/sanitize'
import { buildExportReport } from '../../../src/pcap/export/report'
import { CaptureFormat } from '../../../src/pcap/domain/types'
import { emptyChecksumCounts } from '../../../src/pcap/checksums/types'
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot'

function buildEthIpTcp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
): Uint8Array {
  const tcpLen = 20
  const total = 14 + 20 + tcpLen + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + tcpLen + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  buf[23] = 6
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const tcpStart = 34
  buf[tcpStart] = (srcPort >> 8) & 0xff
  buf[tcpStart + 1] = srcPort & 0xff
  buf[tcpStart + 2] = (dstPort >> 8) & 0xff
  buf[tcpStart + 3] = dstPort & 0xff
  buf[tcpStart + 12] = 0x50
  buf.set(payload, tcpStart + 20)
  return buf
}

function wrapHandshakeRecord(messages: number[]): Uint8Array {
  return new Uint8Array([
    0x16, 0x03, 0x03,
    (messages.length >> 8) & 0xff, messages.length & 0xff,
    ...messages,
  ])
}

function buildClientHello(opts: {
  sni?: string
  echPayloadCanary?: string
  offerTls13?: boolean
}): Uint8Array {
  const extensions: number[] = []

  if (opts.sni) {
    const sniBytes = Array.from(opts.sni, (c) => c.charCodeAt(0))
    const entry = [0x00, (sniBytes.length >> 8) & 0xff, sniBytes.length & 0xff, ...sniBytes]
    const list = [(entry.length >> 8) & 0xff, entry.length & 0xff, ...entry]
    extensions.push(0x00, 0x00, (list.length >> 8) & 0xff, list.length & 0xff, ...list)
  }

  if (opts.offerTls13) {
    // supported_versions: length 2, version TLS 1.3
    const versions = [0x02, 0x03, 0x04]
    extensions.push(0x00, 0x2b, 0x00, versions.length, ...versions)
  }

  if (opts.echPayloadCanary !== undefined) {
    const payload = Array.from(opts.echPayloadCanary, (c) => c.charCodeAt(0))
    const enc = [0xaa, 0xbb]
    // type=outer(0) | cipher_suite(4) | config_id(1) | enc | payload
    const echBody = [
      0x00,
      0x00, 0x01, 0x00, 0x01,
      0x42,
      (enc.length >> 8) & 0xff, enc.length & 0xff, ...enc,
      (payload.length >> 8) & 0xff, payload.length & 0xff, ...payload,
    ]
    extensions.push(0xfe, 0x0d, (echBody.length >> 8) & 0xff, echBody.length & 0xff, ...echBody)
  }

  const random = new Array(32).fill(0x11)
  const cipherSuites = [0x13, 0x01]
  const compression = [0x00]
  const handshakeBody = [
    0x03, 0x03,
    ...random,
    0x00,
    (cipherSuites.length >> 8) & 0xff, cipherSuites.length & 0xff, ...cipherSuites,
    compression.length, ...compression,
    (extensions.length >> 8) & 0xff, extensions.length & 0xff, ...extensions,
  ]
  const handshake = [
    0x01,
    (handshakeBody.length >> 16) & 0xff,
    (handshakeBody.length >> 8) & 0xff,
    handshakeBody.length & 0xff,
    ...handshakeBody,
  ]
  return wrapHandshakeRecord(handshake)
}

function buildTls13ServerHello(): number[] {
  const random = new Array(32).fill(0x22)
  // supported_versions selected = 0x0304
  const ext = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
  const body = [
    0x03, 0x03,
    ...random,
    0x00,
    0x13, 0x01,
    0x00,
    (ext.length >> 8) & 0xff, ext.length & 0xff, ...ext,
  ]
  return [0x02, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body]
}

function buildCertificateWithCn(cn: string, sanIp?: number[]): number[] {
  const cnBytes = Array.from(cn, (c) => c.charCodeAt(0))
  const der: number[] = [
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, cnBytes.length, ...cnBytes,
  ]
  if (sanIp && sanIp.length === 4) {
    der.push(0x87, 0x04, ...sanIp)
  }
  // pad so it looks like a cert body
  der.push(...Array.from('CN=PadSecretCorp', (c) => c.charCodeAt(0)))
  const certList = [
    (der.length >> 16) & 0xff, (der.length >> 8) & 0xff, der.length & 0xff, ...der,
  ]
  const body = [
    (certList.length >> 16) & 0xff, (certList.length >> 8) & 0xff, certList.length & 0xff, ...certList,
  ]
  return [0x0b, (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff, ...body]
}

function applyExport(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const patch of result.patches) out.set(patch.data, patch.offset)
  return out
}

function packetInput(pkt: Uint8Array): PacketInput {
  return {
    index: 0,
    data: pkt,
    capturedLength: pkt.length,
    originalLength: pkt.length,
    linkType: 1,
  }
}

describe('enterprise step 10 — TLS 1.2 / 1.3 / ECH', () => {
  it('TLS 1.2: maps readable cert CN and SAN IP; reports tls-1.2 branch', () => {
    const cn = 'api.customer.example'
    const sanIp = [172, 16, 100, 32]
    const record = wrapHandshakeRecord(buildCertificateWithCn(cn, sanIp))
    const pkt = buildEthIpTcp([10, 0, 0, 2], [192, 168, 1, 1], 443, 40000, record)
    const mapping = new SessionMapping()
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)

    expect(result.issues).toContain('tls-branch:tls-1.2')
    expect(result.coverage.some((c) => c.protocol === 'tls-certificate')).toBe(true)

    const exported = applyExport(pkt, result)
    const text = new TextDecoder('latin1').decode(exported)
    expect(text).not.toContain(cn)
    expect(text).not.toContain('PadSecretCorp')

    const tcpPayload = exported.subarray(14 + 20 + 20)
    const ipSurvives = [...tcpPayload].some((_, i) =>
      i + 4 <= tcpPayload.length
      && tcpPayload[i] === sanIp[0]
      && tcpPayload[i + 1] === sanIp[1]
      && tcpPayload[i + 2] === sanIp[2]
      && tcpPayload[i + 3] === sanIp[3])
    expect(ipSurvives).toBe(false)

    const handling = summarizeTlsHandling({ issues: result.issues, coverage: result.coverage })
    expect(handling.hasTls12).toBe(true)
    expect(handling.branches).toContain('tls-1.2')
  })

  it('findReadableCertIdentities locates CN OID + SAN IP', () => {
    const cn = 'vpn.corp.example'
    const body = new Uint8Array([
      0x06, 0x03, 0x55, 0x04, 0x03,
      0x13, cn.length, ...Array.from(cn, (c) => c.charCodeAt(0)),
      0x87, 0x04, 10, 1, 2, 3,
    ])
    const ids = findReadableCertIdentities(body, 0, body.length)
    expect(ids.some((i) => i.category === 'hostname' && i.value === cn)).toBe(true)
    expect(ids.some((i) => i.category === 'ipv4' && i.value === '10.1.2.3')).toBe(true)
  })

  it('TLS 1.3: Application Data after ServerHello → ENCRYPTED_OPAQUE / tls-1.3 branch', () => {
    const sh = buildTls13ServerHello()
    const shRecord = wrapHandshakeRecord(sh)
    const appData = new Uint8Array([
      0x17, 0x03, 0x03, 0x00, 0x08,
      // pretend EncryptedExtensions ciphertext (8 bytes)
      ...Array.from('ee.secre', (c) => c.charCodeAt(0)),
    ])
    const combined = new Uint8Array(shRecord.length + appData.length)
    combined.set(shRecord, 0)
    combined.set(appData, shRecord.length)

    const pkt = buildEthIpTcp([10, 0, 0, 2], [192, 168, 1, 1], 443, 40000, combined)
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, new SessionMapping())

    expect(result.issues).toContain('tls-branch:tls-1.3')
    expect(result.coverage.some((c) => c.protocol === 'tls-serverhello')).toBe(true)
    const enc = result.coverage.find((c) => c.protocol === 'tls-1.3' && c.status === 'encrypted')
    expect(enc).toBeDefined()

    // Ciphertext preserved (ENCRYPTED_OPAQUE / PRESERVE) — not treated as plaintext SNI to MAP.
    const exported = applyExport(pkt, result)
    // Outer structure: ServerHello session still sanitized; AppData body untouched.
    const appOffset = 14 + 20 + 20 + shRecord.length
    expect(Array.from(exported.subarray(appOffset + 5, appOffset + 5 + 8))).toEqual(
      Array.from('ee.secre', (c) => c.charCodeAt(0)),
    )

    const handling = summarizeTlsHandling({ issues: result.issues, coverage: result.coverage })
    expect(handling.hasTls13).toBe(true)
  })

  it('ECH: Outer public_name SNI mapped; Inner encrypted payload preserved opaque; branch ech', () => {
    const publicName = 'public-ech.cdn.example'
    const innerCanary = 'INNER_CLIENTHELLO_SECRET_HOST'
    const hello = buildClientHello({
      sni: publicName,
      echPayloadCanary: innerCanary,
      offerTls13: true,
    })
    const pkt = buildEthIpTcp([192, 168, 1, 10], [1, 1, 1, 1], 40000, 443, hello)
    const mapping = new SessionMapping()
    const result = sanitizePacket(packetInput(pkt), DIAGNOSTIC_POLICY, mapping)

    expect(result.issues).toContain('tls-branch:ech')
    expect(result.coverage.some((c) => c.protocol === 'tls-clienthello')).toBe(true)
    expect(result.issues.some((i) => i.startsWith('masked-in-place:'))).toBe(false)

    // Direct sanitizeTls fields: ECH payload classified ENCRYPTED_OPAQUE
    const collector = new PatchCollector(hello.length)
    const tlsOnly = sanitizeTls(hello, 0, hello.length, collector, mapping)
    expect(tlsOnly?.fields?.some(
      (f) => f.type === 'tls-ech-payload' && f.classification === 'ENCRYPTED_OPAQUE',
    )).toBe(true)

    const exported = applyExport(pkt, result)
    const text = new TextDecoder('latin1').decode(exported)
    expect(text).not.toContain(publicName)
    // Inner encrypted payload bytes are PRESERVE'd (opaque ciphertext), not parsed as SNI.
    expect(text).toContain(innerCanary)
    // Cipher suite bytes still present — whole ClientHello was not blanked.
    expect(exported.includes(0x13) && exported.includes(0x01)).toBe(true)

    const handling = summarizeTlsHandling({ issues: result.issues })
    expect(handling.hasEch).toBe(true)
    expect(handling.branches).toEqual(['ech'])
  })

  it('report tlsHandling lists observed branches', () => {
    const plan: PcapPlanSnapshot = {
      generationId: 'g-tls-10',
      pcapLevel: 'diagnostic',
      profileId: 'pcap-diagnostic',
      profileHash: 'h',
      format: CaptureFormat.ClassicPcap,
      fileName: 'x.pcap',
      engineVersion: '1.0.0',
      packets: [],
      droppedPacketNumbers: [],
      timestamps: 'relative',
      timestampAnchorSeed: '00',
      changeCategoryTotals: {
        mapped: 0,
        redacted: 0,
        'masked-content': 0,
        'preserved-encrypted': 0,
        'preserved-for-diagnostics': 0,
        'user-requested-drop': 0,
        blocked: 0,
      },
      maskedByteCount: 0,
      dropsByReason: { exported: 0, 'user-requested-drop': 0, blocked: 0 },
      dropsByProtocol: {},
    }
    const report = buildExportReport({
      plan,
      exportedFileName: 'out.pcap',
      changedPackets: 0,
      truncatedPayloads: 0,
      unsupportedLayers: 0,
      protocolCoverage: [{ protocol: 'tls-1.3', packetCount: 1, dominantStatus: 'encrypted' }],
      checksum: { fields: [], counts: emptyChecksumCounts() },
      validation: {
        validationValid: true,
        validationIssueCount: 0,
        newBlockingIssues: [],
        preservedBaselineIssues: [],
      },
      issues: ['tls-branch:ech', 'tls-branch:tls-1.2'],
      coverage: [{ protocol: 'tls-1.3', offset: 0, length: 8, status: 'encrypted' }],
    })
    expect(report.tlsHandling).toBeDefined()
    expect(report.tlsHandling!.branches).toEqual(['tls-1.2', 'tls-1.3', 'ech'])
    expect(report.tlsHandling!.hasEch).toBe(true)
  })
})
