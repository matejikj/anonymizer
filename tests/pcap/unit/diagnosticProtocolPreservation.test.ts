/**
 * @vitest-environment node
 *
 * Step 5 — DNS/DHCP/SIP/TLS/ICMP/ARP diagnostic preservation:
 * message-count parity and independent reparse of anonymized payloads.
 */
import { describe, expect, it } from 'vitest'
import { CaptureFormat, Endian, TimestampResolution } from '../../../src/pcap/domain/types'
import type { ClassicPcapHeader, PacketEnvelope } from '../../../src/pcap/domain/types'
import { createPresetProfile } from '../../../src/pcap/profile/presets'
import { DIAGNOSTIC_POLICY, sanitizeDns, sanitizeDhcpv4, sanitizePacket } from '../../../src/pcap/sanitize'
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { IntentCollector } from '../../../src/pcap/discovery/intentCollector'
import { buildDeterministicPlan } from '../../../src/pcap/plan/deterministicPlanBuilder'
import { resolveSnapshotForPackets } from './pcapSessionTestHelpers'
import { buildCaptureFromPlan } from '../../../src/pcap/export/engine'
import { readClassicPcap } from '../../../src/pcap/capture/pcapReader'
import { classifySipPayload } from '../../../src/pcap/protocols/application/sip/classify'
import { ipv6TextToBytes16 } from '../../../src/pcap/sanitize/ipv6Wire'

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff))
}

function buildEthIpUdp(
  srcIp: number[],
  dstIp: number[],
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
  opts?: { mf?: boolean; fragOffset?: number },
): Uint8Array {
  const total = 14 + 20 + 8 + payload.length
  const buf = new Uint8Array(total)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x00
  buf[14] = 0x45
  const ipTotalLen = 20 + 8 + payload.length
  buf[16] = (ipTotalLen >> 8) & 0xff
  buf[17] = ipTotalLen & 0xff
  const fragOff = opts?.fragOffset ?? 0
  const mf = opts?.mf ? 0x20 : 0
  buf[20] = mf | ((fragOff >> 8) & 0x1f)
  buf[21] = fragOff & 0xff
  buf[23] = 17
  buf.set(srcIp, 26)
  buf.set(dstIp, 30)
  const udp = 34
  buf[udp] = (srcPort >> 8) & 0xff
  buf[udp + 1] = srcPort & 0xff
  buf[udp + 2] = (dstPort >> 8) & 0xff
  buf[udp + 3] = dstPort & 0xff
  const udpLen = 8 + payload.length
  buf[udp + 4] = (udpLen >> 8) & 0xff
  buf[udp + 5] = udpLen & 0xff
  buf.set(payload, udp + 8)
  return buf
}

function buildDnsQuery(hostname: string, id = 0x1234): Uint8Array {
  const labels = hostname.split('.')
  let qnameLen = 1
  for (const l of labels) qnameLen += 1 + l.length
  const dns = new Uint8Array(12 + qnameLen + 4)
  dns[0] = (id >> 8) & 0xff
  dns[1] = id & 0xff
  dns[5] = 1
  let pos = 12
  for (const label of labels) {
    dns[pos++] = label.length
    for (let i = 0; i < label.length; i++) dns[pos++] = label.charCodeAt(i)
  }
  dns[pos++] = 0
  dns[pos + 1] = 1
  dns[pos + 3] = 1
  return dns
}

function buildDnsResponse(hostname: string, ipv4: number[], id = 0x1234): Uint8Array {
  const q = buildDnsQuery(hostname, id)
  const labels = hostname.split('.')
  let nameLen = 1
  for (const l of labels) nameLen += 1 + l.length
  const rr = new Uint8Array(nameLen + 10 + 4)
  let p = 0
  for (const label of labels) {
    rr[p++] = label.length
    for (let i = 0; i < label.length; i++) rr[p++] = label.charCodeAt(i)
  }
  rr[p++] = 0
  rr[p++] = 0
  rr[p++] = 1 // TYPE A
  rr[p++] = 0
  rr[p++] = 1 // CLASS IN
  rr[p++] = 0
  rr[p++] = 0
  rr[p++] = 0
  rr[p++] = 60 // TTL
  rr[p++] = 0
  rr[p++] = 4
  rr.set(ipv4, p)

  const out = new Uint8Array(q.length + rr.length)
  out.set(q)
  out[2] = 0x81 // QR=1, RD=1
  out[3] = 0x80 // RA=1, RCODE=0
  out[7] = 1 // ANCOUNT
  out.set(rr, q.length)
  return out
}

function buildDhcpDiscover(hostname: string, clientMac: number[]): Uint8Array {
  const buf = new Uint8Array(300)
  buf[0] = 1 // BOOTREQUEST
  buf[1] = 1 // Ethernet
  buf[2] = 6 // hlen
  buf.set(clientMac, 28)
  // magic cookie
  buf[236] = 99
  buf[237] = 130
  buf[238] = 83
  buf[239] = 99
  let pos = 240
  // option 53 message type = Discover (1)
  buf[pos++] = 53
  buf[pos++] = 1
  buf[pos++] = 1
  // option 12 hostname
  buf[pos++] = 12
  buf[pos++] = hostname.length
  for (let i = 0; i < hostname.length; i++) buf[pos++] = hostname.charCodeAt(i)
  // option 50 requested IP
  buf[pos++] = 50
  buf[pos++] = 4
  buf.set([192, 168, 99, 50], pos)
  pos += 4
  // option 54 server id
  buf[pos++] = 54
  buf[pos++] = 4
  buf.set([192, 168, 99, 1], pos)
  pos += 4
  // option 3 routers
  buf[pos++] = 3
  buf[pos++] = 4
  buf.set([192, 168, 99, 1], pos)
  pos += 4
  // option 6 DNS
  buf[pos++] = 6
  buf[pos++] = 4
  buf.set([8, 8, 8, 8], pos)
  pos += 4
  buf[pos++] = 255
  return buf
}

function buildSipInvite(): Uint8Array {
  const body = [
    'v=0',
    'o=- 1 1 IN IP4 192.168.55.10',
    's=-',
    'c=IN IP4 192.168.55.10',
    't=0 0',
    'm=audio 55000 RTP/AVP 0',
    '',
  ].join('\r\n')
  const text = [
    'INVITE sip:bob@192.168.55.20 SIP/2.0',
    'Via: SIP/2.0/UDP 192.168.55.10:5060;branch=z9hG4bKdiag5',
    'From: <sip:alice@192.168.55.10>;tag=diagfrom',
    'To: <sip:bob@192.168.55.20>',
    'Call-ID: diag-step5-call@192.168.55.10',
    'CSeq: 1 INVITE',
    'Contact: <sip:alice@192.168.55.10:5060>',
    `Content-Length: ${body.length}`,
    'Content-Type: application/sdp',
    '',
    body,
  ].join('\r\n')
  return latin1(text)
}

function buildArpRequest(): Uint8Array {
  // Ethernet (14) + ARP (28) + padding to 60
  const buf = new Uint8Array(60)
  buf.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0)
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6)
  buf[12] = 0x08
  buf[13] = 0x06
  const arp = 14
  buf[arp] = 0x00
  buf[arp + 1] = 0x01 // HTYPE Ethernet
  buf[arp + 2] = 0x08
  buf[arp + 3] = 0x00 // PTYPE IPv4
  buf[arp + 4] = 6
  buf[arp + 5] = 4
  buf[arp + 6] = 0x00
  buf[arp + 7] = 0x01 // request
  buf.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], arp + 8)
  buf.set([192, 168, 1, 10], arp + 14)
  buf.set([0, 0, 0, 0, 0, 0], arp + 18)
  buf.set([192, 168, 1, 1], arp + 24)
  // padding filled with canary
  buf.fill(0xa5, arp + 28)
  return buf
}

function envelope(data: Uint8Array, index: number): PacketEnvelope {
  return {
    packetNumber: index + 1,
    timestamp: { ticks: BigInt(index), unitsPerSecond: 1_000_000n, offsetSeconds: 0n },
    capturedLength: data.length,
    originalLength: data.length,
    linkType: 1,
    interfaceId: 0,
    sectionIndex: 0,
    fileOffset: 0,
    data,
  }
}

function classicHeader(): ClassicPcapHeader {
  return {
    format: CaptureFormat.ClassicPcap,
    endian: Endian.Little,
    timestampResolution: TimestampResolution.Microseconds,
    versionMajor: 2,
    versionMinor: 4,
    snapLen: 65535,
    linkType: 1,
    tzOffset: 0,
    sigfigs: 0,
  }
}

function udpPayload(frame: Uint8Array): Uint8Array {
  return frame.subarray(14 + 20 + 8)
}

function dnsHeader(payload: Uint8Array): {
  id: number
  flags: number
  qd: number
  an: number
  rcode: number
} {
  return {
    id: (payload[0]! << 8) | payload[1]!,
    flags: (payload[2]! << 8) | payload[3]!,
    qd: (payload[4]! << 8) | payload[5]!,
    an: (payload[6]! << 8) | payload[7]!,
    rcode: payload[3]! & 0xf,
  }
}

describe('ipv6 wire helper (step 5)', () => {
  it('expands compressed :: correctly', () => {
    const bytes = ipv6TextToBytes16('2001:db8::1')
    expect(bytes).not.toBeNull()
    expect(bytes![0]).toBe(0x20)
    expect(bytes![1]).toBe(0x01)
    expect(bytes![2]).toBe(0x0d)
    expect(bytes![3]).toBe(0xb8)
    expect(bytes![14]).toBe(0x00)
    expect(bytes![15]).toBe(0x01)
  })
})

describe('DNS/DHCP discovery intents (step 5)', () => {
  it('records hostname entity-replacement for DNS queries', () => {
    const hostname = 'secret-dns.diag.example'
    const pkt = buildEthIpUdp([10, 0, 0, 1], [8, 8, 8, 8], 53000, 53, buildDnsQuery(hostname))
    const intents = new IntentCollector()
    sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
      { intents },
    )
    const hostIntents = intents.intents.filter(
      (i) => i.kind === 'entity-replacement' && i.category === 'hostname',
    )
    expect(hostIntents.some((i) => i.kind === 'entity-replacement' && i.canonical.includes('secret-dns'))).toBe(
      true,
    )
  })

  it('records DHCP hostname and IPv4 option intents', () => {
    const pkt = buildEthIpUdp(
      [0, 0, 0, 0],
      [255, 255, 255, 255],
      68,
      67,
      buildDhcpDiscover('client-host.diag', [0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]),
    )
    const intents = new IntentCollector()
    sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
      { intents },
    )
    expect(
      intents.intents.some(
        (i) => i.kind === 'entity-replacement' && i.category === 'hostname' && i.canonical.includes('client-host'),
      ),
    ).toBe(true)
    expect(intents.intents.some((i) => i.kind === 'entity-replacement' && i.category === 'ipv4')).toBe(true)
  })
})

describe('first-fragment L4 decode (step 5)', () => {
  it('still sanitizes DNS on first fragment (MF=1, offset=0)', () => {
    const hostname = 'frag-dns.diag.example'
    const pkt = buildEthIpUdp([10, 0, 0, 1], [8, 8, 8, 8], 53000, 53, buildDnsQuery(hostname), {
      mf: true,
      fragOffset: 0,
    })
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    )
    expect(result.coverage.some((c) => c.protocol === 'dns' && c.status === 'covered')).toBe(true)
    expect(result.issues.some((i) => i.includes('non-first fragment'))).toBe(false)
  })

  it('skips transport on non-first fragment', () => {
    const pkt = buildEthIpUdp([10, 0, 0, 1], [8, 8, 8, 8], 53000, 53, buildDnsQuery('x.example'), {
      fragOffset: 185, // units of 8 bytes
    })
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    )
    expect(result.coverage.some((c) => c.protocol === 'fragment')).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'dns')).toBe(false)
  })
})

describe('ARP padding (step 5)', () => {
  it('zeros Ethernet padding after ARP body without changing frame length', () => {
    const pkt = buildArpRequest()
    const result = sanitizePacket(
      { index: 0, data: pkt, capturedLength: pkt.length, originalLength: pkt.length, linkType: 1 },
      DIAGNOSTIC_POLICY,
      new SessionMapping(),
    )
    expect(result.truncatedLength).toBeUndefined()
    const out = pkt.slice()
    for (const p of result.patches) out.set(p.data, p.offset)
    expect(out.length).toBe(60)
    expect([...out.subarray(42)].every((b) => b === 0)).toBe(true)
    expect(result.coverage.some((c) => c.protocol === 'arp-padding' && c.status === 'redacted')).toBe(true)
  })
})

describe('diagnostic protocol preservation (step 5 acceptance)', () => {
  it('keeps DNS/DHCP/SIP message counts and independently reparses types', () => {
    const dnsHost = 'lookup.diag.example'
    const dhcpHost = 'dhcp-client.diag'
    const packets = [
      envelope(
        buildEthIpUdp([192, 168, 55, 10], [8, 8, 8, 8], 53000, 53, buildDnsQuery(dnsHost, 0xabcd)),
        0,
      ),
      envelope(
        buildEthIpUdp(
          [8, 8, 8, 8],
          [192, 168, 55, 10],
          53,
          53000,
          buildDnsResponse(dnsHost, [93, 184, 216, 34], 0xabcd),
        ),
        1,
      ),
      envelope(
        buildEthIpUdp(
          [0, 0, 0, 0],
          [255, 255, 255, 255],
          68,
          67,
          buildDhcpDiscover(dhcpHost, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        ),
        2,
      ),
      envelope(buildEthIpUdp([192, 168, 55, 10], [192, 168, 55, 20], 5060, 5060, buildSipInvite()), 3),
    ]

    const beforeDnsCount = packets.filter((_, i) => i === 0 || i === 1).length
    const beforeDhcpCount = 1
    const beforeSipCount = 1

    const beforeDnsHdr = [
      dnsHeader(udpPayload(packets[0]!.data)),
      dnsHeader(udpPayload(packets[1]!.data)),
    ]
    const beforeDhcpType = udpPayload(packets[2]!.data)[242]! // option 53 value
    const beforeSipClassified = classifySipPayload(
      packets[3]!.data,
      14 + 20 + 8,
      packets[3]!.data.length - (14 + 20 + 8),
      { portHint: true },
    )
    expect(beforeSipClassified.kind).toBe('complete')
    if (beforeSipClassified.kind !== 'complete') return
    expect(beforeSipClassified.message.startLine.kind).toBe('request')

    const profile = createPresetProfile('diagnostic')
    const policy = DIAGNOSTIC_POLICY
    const snapshot = resolveSnapshotForPackets(packets, policy, 'step5-gen', 'step5.pcap')
    const plan = buildDeterministicPlan({
      generationId: 'step5-gen',
      profile,
      format: CaptureFormat.ClassicPcap,
      fileName: 'step5.pcap',
      packets,
      policy,
      snapshot,
      classicHeader: classicHeader(),
    })

    expect(plan.packets).toHaveLength(packets.length)
    for (const p of plan.packets) {
      expect(p.drop).toBe(false)
      expect(p.truncatedLength).toBeUndefined()
    }

    const built = buildCaptureFromPlan(plan, packets)
    const reread = readClassicPcap(built.buffer)
    expect(reread.packets).toHaveLength(packets.length)

    let dnsCount = 0
    let dhcpCount = 0
    let sipCount = 0

    for (let i = 0; i < reread.packets.length; i++) {
      const frame = reread.packets[i]!.data
      const payload = udpPayload(frame)
      if (i === 0 || i === 1) {
        dnsCount++
        const hdr = dnsHeader(payload)
        expect(hdr.id).toBe(beforeDnsHdr[i]!.id)
        expect(hdr.flags).toBe(beforeDnsHdr[i]!.flags)
        expect(hdr.qd).toBe(beforeDnsHdr[i]!.qd)
        expect(hdr.an).toBe(beforeDnsHdr[i]!.an)
        expect(hdr.rcode).toBe(beforeDnsHdr[i]!.rcode)
        // Independent reparse via sanitizer on anonymized bytes
        const ok = sanitizeDns(payload, 0, payload.length, new PatchCollector(payload.length), new SessionMapping())
        expect(ok).toBe(true)
        expect(new TextDecoder('latin1').decode(payload)).not.toContain(dnsHost)
      } else if (i === 2) {
        dhcpCount++
        expect(payload[242]).toBe(beforeDhcpType) // Discover
        expect(payload[0]).toBe(1) // BOOTREQUEST
        const ok = sanitizeDhcpv4(payload, 0, payload.length, new PatchCollector(payload.length), new SessionMapping())
        expect(ok).toBe(true)
        expect(new TextDecoder('latin1').decode(payload)).not.toContain(dhcpHost)
      } else if (i === 3) {
        sipCount++
        const classified = classifySipPayload(frame, 14 + 20 + 8, payload.length, { portHint: true })
        expect(classified.kind).toBe('complete')
        if (classified.kind === 'complete') {
          expect(classified.message.startLine.kind).toBe('request')
          if (classified.message.startLine.kind === 'request') {
            expect(classified.message.startLine.methodText).toBe('INVITE')
          }
        }
        expect(new TextDecoder('latin1').decode(payload)).not.toContain('192.168.55.10')
      }
    }

    expect(dnsCount).toBe(beforeDnsCount)
    expect(dhcpCount).toBe(beforeDhcpCount)
    expect(sipCount).toBe(beforeSipCount)
  })
})
