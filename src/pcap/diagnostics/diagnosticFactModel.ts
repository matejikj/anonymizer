/**
 * Identity-agnostic diagnostic fact model (step 10).
 * Compares original vs anonymized captures without relying on IP/MAC/hostname values.
 */

import { locateLayers } from '../checksums/locate'
import type { PacketEnvelope } from '../domain/types'

export type DiagnosticRootCauseCategory =
  | 'dns-nxdomain'
  | 'dns-timeout'
  | 'dhcp-no-ack'
  | 'sip-401-auth'
  | 'sip-register-failure'
  | 'sip-4xx'
  | 'sip-5xx'
  | 'tcp-reset'
  | 'tcp-retransmission'
  | 'tcp-zero-window'
  | 'rtp-loss'
  | 'rtp-jitter'
  | 'rtp-out-of-order'
  | 'rtcp-quality-degrade'
  | 'none'

export interface DiagnosticPacketFact {
  readonly packetNumber: number
  readonly protocols: readonly string[]
  readonly ethertype: number | null
  readonly hasVlan: boolean
  readonly ipVersion: 4 | 6 | null
  readonly l4: 'tcp' | 'udp' | 'icmpv4' | 'icmpv6' | null
  readonly tcp: {
    readonly flags: number
    readonly window: number
    readonly seq: number
    readonly syn: boolean
    readonly rst: boolean
    readonly fin: boolean
    readonly windowZero: boolean
    /** Identity-agnostic: same SEQ as previous TCP packet (retransmission signal). */
    readonly sameSeqAsPrev: boolean
  } | null
  readonly icmp: { readonly type: number; readonly code: number } | null
  readonly dns: {
    readonly id: number
    readonly qr: boolean
    readonly rcode: number
    readonly opcode: number
    readonly qdcount: number
    readonly ancount: number
  } | null
  readonly dhcp: { readonly op: number; readonly msgType: number | null } | null
  readonly sip: {
    readonly kind: 'request' | 'response'
    readonly method: string | null
    readonly status: number | null
  } | null
  readonly rtp: {
    readonly seq: number
    readonly pt: number
    readonly marker: boolean
    readonly version: number
  } | null
  readonly rtcp: {
    readonly pt: number
    readonly fractionLost: number | null
    readonly jitter: number | null
  } | null
  readonly capturedLength: number
  readonly originalLength: number
  /** Relative timing from previous packet (identity-agnostic). */
  readonly relativeTicksFromPrev: string
}

export interface DiagnosticFactModel {
  readonly packetCount: number
  readonly packets: readonly DiagnosticPacketFact[]
  readonly rootCauseCategory: DiagnosticRootCauseCategory
  readonly evidencePacketNumbers: readonly number[]
}

export interface DiagnosticFactDiff {
  readonly equal: boolean
  readonly mismatches: readonly string[]
}

function readU16(data: Uint8Array, offset: number): number {
  return ((data[offset]! << 8) | data[offset + 1]!) >>> 0
}

function udpPayload(data: Uint8Array, linkType: number): Uint8Array | null {
  const layers = locateLayers(data, linkType, data.length)
  if (layers.l4Proto !== 'udp' || layers.l4Offset + 8 > data.length) return null
  return data.subarray(layers.l4Offset + 8)
}

function tcpPayload(data: Uint8Array, linkType: number): Uint8Array | null {
  const layers = locateLayers(data, linkType, data.length)
  if (layers.l4Proto !== 'tcp' || layers.l4Offset + 20 > data.length) return null
  const dataOff = layers.l4Offset + ((data[layers.l4Offset + 12]! >> 4) * 4)
  if (dataOff > data.length) return null
  return data.subarray(dataOff)
}

function parseDns(payload: Uint8Array): DiagnosticPacketFact['dns'] {
  if (payload.length < 12) return null
  const flags = readU16(payload, 2)
  return {
    id: readU16(payload, 0),
    qr: (flags & 0x8000) !== 0,
    opcode: (flags >> 11) & 0xf,
    rcode: flags & 0xf,
    qdcount: readU16(payload, 4),
    ancount: readU16(payload, 6),
  }
}

function parseDhcp(payload: Uint8Array): DiagnosticPacketFact['dhcp'] {
  if (payload.length < 240) return null
  if (payload[236] !== 99 || payload[237] !== 130 || payload[238] !== 83 || payload[239] !== 99) {
    return null
  }
  let msgType: number | null = null
  let pos = 240
  while (pos + 1 < payload.length) {
    const code = payload[pos]!
    if (code === 255) break
    if (code === 0) {
      pos++
      continue
    }
    const len = payload[pos + 1]!
    if (pos + 2 + len > payload.length) break
    if (code === 53 && len >= 1) msgType = payload[pos + 2]!
    pos += 2 + len
  }
  return { op: payload[0]!, msgType }
}

function parseSip(payload: Uint8Array): DiagnosticPacketFact['sip'] {
  if (payload.length < 8) return null
  let end = 0
  while (end < payload.length && payload[end] !== 0x0d && payload[end] !== 0x0a) end++
  const line = new TextDecoder('latin1').decode(payload.subarray(0, end))
  if (/^SIP\/2\.0\s+(\d{3})\b/i.test(line)) {
    const status = Number.parseInt(RegExp.$1, 10)
    return { kind: 'response', method: null, status }
  }
  const req = /^(INVITE|REGISTER|ACK|BYE|CANCEL|OPTIONS|INFO|UPDATE|PRACK|SUBSCRIBE|NOTIFY|REFER|MESSAGE|PUBLISH)\s+/i.exec(line)
  if (req) {
    return { kind: 'request', method: req[1]!.toUpperCase(), status: null }
  }
  return null
}

function parseRtp(payload: Uint8Array): DiagnosticPacketFact['rtp'] {
  if (payload.length < 12) return null
  const v = (payload[0]! >> 6) & 0x3
  if (v !== 2) return null
  const pt = payload[1]! & 0x7f
  // Exclude RTCP PT range commonly used for compound packets
  if (pt >= 72 && pt <= 76) return null
  return {
    version: v,
    marker: (payload[1]! & 0x80) !== 0,
    pt,
    seq: readU16(payload, 2),
  }
}

function parseRtcp(payload: Uint8Array): DiagnosticPacketFact['rtcp'] {
  if (payload.length < 8) return null
  const v = (payload[0]! >> 6) & 0x3
  if (v !== 2) return null
  const pt = payload[1]!
  if (pt < 200 || pt > 207) return null
  let fractionLost: number | null = null
  let jitter: number | null = null
  if (pt === 201 && payload.length >= 32) {
    // Receiver Report: SSRC(4) + report block starts at +8 from header body
    fractionLost = payload[12]!
    jitter =
      ((payload[20]! << 24) | (payload[21]! << 16) | (payload[22]! << 8) | payload[23]!) >>> 0
  }
  return { pt, fractionLost, jitter }
}

function extractAppFacts(
  data: Uint8Array,
  linkType: number,
  protocols: string[],
): Pick<DiagnosticPacketFact, 'dns' | 'dhcp' | 'sip' | 'rtp' | 'rtcp'> {
  const layers = locateLayers(data, linkType, data.length)
  const ports: number[] = []
  if (layers.l4Proto === 'udp' || layers.l4Proto === 'tcp') {
    ports.push(readU16(data, layers.l4Offset), readU16(data, layers.l4Offset + 2))
  }
  const payload =
    layers.l4Proto === 'udp'
      ? udpPayload(data, linkType)
      : layers.l4Proto === 'tcp'
        ? tcpPayload(data, linkType)
        : null

  let dns: DiagnosticPacketFact['dns'] = null
  let dhcp: DiagnosticPacketFact['dhcp'] = null
  let sip: DiagnosticPacketFact['sip'] = null
  let rtp: DiagnosticPacketFact['rtp'] = null
  let rtcp: DiagnosticPacketFact['rtcp'] = null

  if (payload) {
    if (ports.includes(53) || ports.includes(5353)) {
      dns = parseDns(payload)
      if (dns) protocols.push(ports.includes(5353) ? 'mdns' : 'dns')
    }
    if (ports.includes(67) || ports.includes(68)) {
      dhcp = parseDhcp(payload)
      if (dhcp) protocols.push('dhcp')
    }
    if (ports.includes(5060) || ports.includes(5061) || payload[0] === 0x49 /* I */ || payload[0] === 0x53 /* S */) {
      sip = parseSip(payload)
      if (sip) protocols.push('sip')
    }
    if (!sip && !dns && !dhcp) {
      rtcp = parseRtcp(payload)
      if (rtcp) {
        protocols.push('rtcp')
      } else {
        rtp = parseRtp(payload)
        if (rtp) protocols.push('rtp')
      }
    }
    if (payload[0] === 0x16 && payload[1] === 0x03) protocols.push('tls')
    else if (ports.includes(443) || ports.includes(5061)) protocols.push('tls')
  }
  return { dns, dhcp, sip, rtp, rtcp }
}

export function extractPacketFact(
  packet: PacketEnvelope,
  prevTicks: bigint | null,
  prevTcpSeq: number | null = null,
): DiagnosticPacketFact {
  const data = packet.data
  const layers = locateLayers(data, packet.linkType, data.length)
  const protocols: string[] = ['ethernet']
  let ethertype: number | null = null
  let hasVlan = false

  if (packet.linkType === 1 && data.length >= 14) {
    let off = 12
    ethertype = readU16(data, off)
    if (ethertype === 0x8100 && data.length >= 18) {
      hasVlan = true
      protocols.push('vlan')
      ethertype = readU16(data, 16)
    }
  }

  let ipVersion: 4 | 6 | null = null
  if (layers.l3Proto === 'ipv4') {
    ipVersion = 4
    protocols.push('ipv4')
  } else if (layers.l3Proto === 'ipv6') {
    ipVersion = 6
    protocols.push('ipv6')
  } else if (layers.l3Proto === 'arp') {
    protocols.push('arp')
  }

  let l4: DiagnosticPacketFact['l4'] = null
  let tcp: DiagnosticPacketFact['tcp'] = null
  let icmp: DiagnosticPacketFact['icmp'] = null

  if (layers.l4Proto === 'tcp') {
    l4 = 'tcp'
    protocols.push('tcp')
    const flags = data[layers.l4Offset + 13]!
    const window = readU16(data, layers.l4Offset + 14)
    const seq =
      ((data[layers.l4Offset + 4]! << 24) |
        (data[layers.l4Offset + 5]! << 16) |
        (data[layers.l4Offset + 6]! << 8) |
        data[layers.l4Offset + 7]!) >>>
      0
    tcp = {
      flags,
      window,
      seq,
      syn: (flags & 0x02) !== 0,
      rst: (flags & 0x04) !== 0,
      fin: (flags & 0x01) !== 0,
      windowZero: window === 0,
      sameSeqAsPrev: prevTcpSeq !== null && prevTcpSeq === seq,
    }
  } else if (layers.l4Proto === 'udp') {
    l4 = 'udp'
    protocols.push('udp')
  } else if (layers.l4Proto === 'icmpv4') {
    l4 = 'icmpv4'
    protocols.push('icmp')
    icmp = { type: data[layers.l4Offset]!, code: data[layers.l4Offset + 1]! }
  } else if (layers.l4Proto === 'icmpv6') {
    l4 = 'icmpv6'
    protocols.push('icmpv6')
    icmp = { type: data[layers.l4Offset]!, code: data[layers.l4Offset + 1]! }
  }

  const app = extractAppFacts(data, packet.linkType, protocols)
  const ticks = packet.timestamp.ticks
  const relativeTicksFromPrev =
    prevTicks === null ? '0' : (ticks - prevTicks).toString()

  return {
    packetNumber: packet.packetNumber,
    protocols,
    ethertype,
    hasVlan,
    ipVersion,
    l4,
    tcp,
    icmp,
    dns: app.dns,
    dhcp: app.dhcp,
    sip: app.sip,
    rtp: app.rtp,
    rtcp: app.rtcp,
    capturedLength: packet.capturedLength,
    originalLength: packet.originalLength,
    relativeTicksFromPrev,
  }
}

export function inferRootCause(packets: readonly DiagnosticPacketFact[]): {
  readonly rootCauseCategory: DiagnosticRootCauseCategory
  readonly evidencePacketNumbers: readonly number[]
} {
  const evidence: number[] = []

  for (const p of packets) {
    if (p.dns && p.dns.qr && p.dns.rcode === 3) {
      return { rootCauseCategory: 'dns-nxdomain', evidencePacketNumbers: [p.packetNumber] }
    }
  }

  const dhcpTypes = new Map<number, number>()
  for (const p of packets) {
    if (p.dhcp?.msgType != null) {
      dhcpTypes.set(p.dhcp.msgType, p.packetNumber)
      evidence.push(p.packetNumber)
    }
  }
  if (dhcpTypes.size > 0 && !dhcpTypes.has(5 /* ACK */)) {
    return { rootCauseCategory: 'dhcp-no-ack', evidencePacketNumbers: [...new Set(evidence)] }
  }

  for (const p of packets) {
    if (p.sip?.status === 401) {
      return { rootCauseCategory: 'sip-401-auth', evidencePacketNumbers: [p.packetNumber] }
    }
  }
  for (const p of packets) {
    if (p.sip?.kind === 'response' && p.sip.status != null && p.sip.status >= 500) {
      return { rootCauseCategory: 'sip-5xx', evidencePacketNumbers: [p.packetNumber] }
    }
  }
  for (const p of packets) {
    if (p.sip?.kind === 'response' && p.sip.status != null && p.sip.status >= 400) {
      const cat: DiagnosticRootCauseCategory =
        p.sip.method === 'REGISTER' || packets.some((x) => x.sip?.method === 'REGISTER')
          ? 'sip-register-failure'
          : 'sip-4xx'
      return { rootCauseCategory: cat, evidencePacketNumbers: [p.packetNumber] }
    }
  }

  for (const p of packets) {
    if (p.tcp?.rst) {
      return { rootCauseCategory: 'tcp-reset', evidencePacketNumbers: [p.packetNumber] }
    }
  }
  for (const p of packets) {
    if (p.tcp?.windowZero) {
      return { rootCauseCategory: 'tcp-zero-window', evidencePacketNumbers: [p.packetNumber] }
    }
  }
  for (let i = 1; i < packets.length; i++) {
    const prev = packets[i - 1]!
    const cur = packets[i]!
    if (cur.tcp?.sameSeqAsPrev && prev.tcp && !prev.tcp.syn) {
      return {
        rootCauseCategory: 'tcp-retransmission',
        evidencePacketNumbers: [prev.packetNumber, cur.packetNumber],
      }
    }
  }

  const rtpByPt = new Map<number, DiagnosticPacketFact[]>()
  for (const p of packets) {
    if (!p.rtp) continue
    const list = rtpByPt.get(p.rtp.pt) ?? []
    list.push(p)
    rtpByPt.set(p.rtp.pt, list)
  }
  for (const list of rtpByPt.values()) {
    for (let i = 1; i < list.length; i++) {
      const prev = list[i - 1]!.rtp!
      const cur = list[i]!.rtp!
      const delta = (cur.seq - prev.seq + 0x10000) % 0x10000
      if (delta === 0) continue
      if (delta > 1 && delta < 0x8000) {
        return {
          rootCauseCategory: 'rtp-loss',
          evidencePacketNumbers: [list[i - 1]!.packetNumber, list[i]!.packetNumber],
        }
      }
      if (delta > 0x8000) {
        return {
          rootCauseCategory: 'rtp-out-of-order',
          evidencePacketNumbers: [list[i - 1]!.packetNumber, list[i]!.packetNumber],
        }
      }
    }
  }

  for (const p of packets) {
    if (p.rtcp?.fractionLost != null && p.rtcp.fractionLost >= 64) {
      return { rootCauseCategory: 'rtcp-quality-degrade', evidencePacketNumbers: [p.packetNumber] }
    }
    if (p.rtcp?.jitter != null && p.rtcp.jitter >= 5000) {
      return { rootCauseCategory: 'rtp-jitter', evidencePacketNumbers: [p.packetNumber] }
    }
  }

  // Explicit DNS query without matching response id → timeout signal
  const queries = packets.filter((p) => p.dns && !p.dns.qr)
  const responses = new Set(packets.filter((p) => p.dns?.qr).map((p) => p.dns!.id))
  for (const q of queries) {
    if (!responses.has(q.dns!.id)) {
      return { rootCauseCategory: 'dns-timeout', evidencePacketNumbers: [q.packetNumber] }
    }
  }

  for (const p of packets) {
    if (p.tcp && (p.tcp.flags & 0x04) === 0 && p.relativeTicksFromPrev !== '0') {
      // leave default
    }
  }

  return { rootCauseCategory: 'none', evidencePacketNumbers: [] }
}

export function buildDiagnosticFactModel(
  packets: readonly PacketEnvelope[],
  forcedRootCause?: DiagnosticRootCauseCategory,
): DiagnosticFactModel {
  const facts: DiagnosticPacketFact[] = []
  let prevTicks: bigint | null = null
  let prevTcpSeq: number | null = null
  for (const pkt of packets) {
    const fact = extractPacketFact(pkt, prevTicks, prevTcpSeq)
    facts.push(fact)
    prevTicks = pkt.timestamp.ticks
    prevTcpSeq = fact.tcp?.seq ?? null
  }
  const inferred = inferRootCause(facts)
  return {
    packetCount: facts.length,
    packets: facts,
    rootCauseCategory: forcedRootCause ?? inferred.rootCauseCategory,
    evidencePacketNumbers:
      forcedRootCause != null && forcedRootCause !== 'none'
        ? inferred.evidencePacketNumbers.length > 0
          ? inferred.evidencePacketNumbers
          : facts.map((f) => f.packetNumber)
        : inferred.evidencePacketNumbers,
  }
}

function factSignature(f: DiagnosticPacketFact): string {
  return JSON.stringify({
    packetNumber: f.packetNumber,
    protocols: f.protocols,
    ethertype: f.ethertype,
    hasVlan: f.hasVlan,
    ipVersion: f.ipVersion,
    l4: f.l4,
    tcp: f.tcp
      ? {
          flags: f.tcp.flags,
          windowZero: f.tcp.windowZero,
          syn: f.tcp.syn,
          rst: f.tcp.rst,
          fin: f.tcp.fin,
          sameSeqAsPrev: f.tcp.sameSeqAsPrev,
        }
      : null,
    icmp: f.icmp,
    dns: f.dns
      ? {
          qr: f.dns.qr,
          rcode: f.dns.rcode,
          opcode: f.dns.opcode,
          qdcount: f.dns.qdcount,
          ancount: f.dns.ancount,
        }
      : null,
    dhcp: f.dhcp,
    sip: f.sip,
    rtp: f.rtp
      ? { seq: f.rtp.seq, pt: f.rtp.pt, marker: f.rtp.marker, version: f.rtp.version }
      : null,
    rtcp: f.rtcp
      ? {
          pt: f.rtcp.pt,
          fractionLost: f.rtcp.fractionLost,
          // jitter may be preserved; compare presence band only when set
          highJitter: f.rtcp.jitter != null ? f.rtcp.jitter >= 5000 : null,
        }
      : null,
    capturedLength: f.capturedLength,
    originalLength: f.originalLength,
    relativeTicksFromPrev: f.relativeTicksFromPrev,
  })
}

/**
 * Compare identity-agnostic facts. DNS transaction ids may be preserved;
 * hostnames/IPs are not part of the signature.
 */
export function compareDiagnosticFactModels(
  original: DiagnosticFactModel,
  anonymized: DiagnosticFactModel,
): DiagnosticFactDiff {
  const mismatches: string[] = []
  if (original.packetCount !== anonymized.packetCount) {
    mismatches.push(`packetCount ${original.packetCount}→${anonymized.packetCount}`)
  }
  if (original.rootCauseCategory !== anonymized.rootCauseCategory) {
    mismatches.push(
      `rootCause ${original.rootCauseCategory}→${anonymized.rootCauseCategory}`,
    )
  }
  const aEvidence = [...original.evidencePacketNumbers].sort((x, y) => x - y).join(',')
  const bEvidence = [...anonymized.evidencePacketNumbers].sort((x, y) => x - y).join(',')
  if (aEvidence !== bEvidence) {
    mismatches.push(`evidencePackets [${aEvidence}]→[${bEvidence}]`)
  }

  const n = Math.min(original.packets.length, anonymized.packets.length)
  for (let i = 0; i < n; i++) {
    const a = original.packets[i]!
    const b = anonymized.packets[i]!
    if (a.packetNumber !== b.packetNumber) {
      mismatches.push(`packet[${i}].packetNumber ${a.packetNumber}→${b.packetNumber}`)
    }
    const sa = factSignature(a)
    const sb = factSignature(b)
    if (sa !== sb) {
      mismatches.push(`packet[${i}]#${a.packetNumber} fact mismatch`)
    }
  }
  return { equal: mismatches.length === 0, mismatches }
}
