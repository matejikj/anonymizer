/**
 * DHCPv4/v6 options are fail-closed: identity-free parameters stay, address/name layouts are
 * mapped, everything else (classless route destinations, WPAD URL, vendor/relay data, status
 * text, delegated prefixes, relay link/peer addresses) is masked in place.
 */

import { describe, expect, it } from 'vitest'
import { SessionMapping } from '../../../src/pcap/anonymization/mapping'
import { sanitizePacket, DIAGNOSTIC_POLICY, HIGH_PRIVACY_POLICY } from '../../../src/pcap/sanitize'
import { buildEthIpUdp } from '../fixtures/voipCorpus'

const UDP_PAYLOAD_OFFSET = 14 + 20 + 8

function packetInput(data: Uint8Array) {
  return { index: 0, data, capturedLength: data.length, originalLength: data.length, linkType: 1 }
}

function applyPatches(original: Uint8Array, result: ReturnType<typeof sanitizePacket>): Uint8Array {
  const out = original.slice()
  for (const p of result.patches) out.set(p.data, p.offset)
  return out
}

function ascii(s: string): number[] {
  return [...s].map((ch) => ch.charCodeAt(0))
}

function contains(haystack: Uint8Array, needle: readonly number[]): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer
    return true
  }
  return false
}

function ipv6(text: string): number[] {
  const [head, tail = ''] = text.split('::')
  const h = head ? head.split(':') : []
  const t = tail ? tail.split(':') : []
  const groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t]
  return groups.flatMap((g) => {
    const v = parseInt(g, 16)
    return [v >> 8, v & 0xff]
  })
}

interface Option {
  readonly code: number
  readonly value: readonly number[]
}

/** BOOTREPLY (DHCPACK) with the given options; returns option value offsets in the UDP payload. */
function buildDhcpv4Ack(options: readonly Option[]): { payload: Uint8Array; valueOffsets: Map<number, number> } {
  const bytes: number[] = Array(240).fill(0)
  bytes[0] = 2 // BOOTREPLY
  bytes[1] = 1
  bytes[2] = 6
  bytes.splice(16, 4, 192, 0, 2, 50) // yiaddr
  bytes.splice(28, 6, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55) // chaddr
  bytes.splice(236, 4, 99, 130, 83, 99)
  const valueOffsets = new Map<number, number>()
  for (const opt of options) {
    bytes.push(opt.code, opt.value.length)
    valueOffsets.set(opt.code, bytes.length)
    bytes.push(...opt.value)
  }
  bytes.push(255)
  return { payload: new Uint8Array(bytes), valueOffsets }
}

/** BOOTREPLY with raw header fields and a raw option byte stream after the magic cookie. */
function buildDhcpv4Raw(input: {
  hlen?: number
  chaddr?: readonly number[]
  sname?: readonly number[]
  file?: readonly number[]
  options: readonly number[]
}): Uint8Array {
  const bytes = new Uint8Array(240 + input.options.length)
  bytes[0] = 2
  bytes[1] = 1
  bytes[2] = input.hlen ?? 6
  bytes.set(input.chaddr ?? [0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 28)
  bytes.set(input.sname ?? [], 44)
  bytes.set(input.file ?? [], 108)
  bytes.set([99, 130, 83, 99], 236)
  bytes.set(input.options, 240)
  return bytes
}

function sanitizeFrame(frame: Uint8Array, policy: typeof DIAGNOSTIC_POLICY, seed: string): Uint8Array {
  return applyPatches(frame, sanitizePacket(packetInput(frame), policy, new SessionMapping(undefined, { seed })))
}

/** Bytes left identical in a masked region (a mask fill may coincide with the original by chance). */
function unchangedCount(original: Uint8Array, out: Uint8Array, offset: number, length: number): number {
  let same = 0
  for (let i = offset; i < offset + length; i++) if (original[i] === out[i]) same++
  return same
}

function dhcpv6Option(code: number, value: readonly number[]): number[] {
  return [code >> 8, code & 0xff, value.length >> 8, value.length & 0xff, ...value]
}

function dnsName(name: string): number[] {
  return [...name.split('.').filter(Boolean).flatMap((label) => [label.length, ...ascii(label)]), 0]
}

describe('DHCPv4 fail-closed options', () => {
  const routerIp = [192, 0, 2, 1]
  const dnsIp = [198, 51, 100, 53]
  const wpad = 'http://198.51.100.7/wpad.dat'
  const circuitId = 'rgw-port-7'
  const options: Option[] = [
    { code: 53, value: [5] }, // DHCPACK
    { code: 1, value: [255, 255, 255, 0] },
    { code: 51, value: [0, 1, 81, 128] },
    { code: 3, value: routerIp },
    { code: 6, value: dnsIp },
    // 0.0.0.0/0 via router, 10.20.0.0/16 via router
    { code: 121, value: [0, ...routerIp, 16, 10, 20, ...routerIp] },
    { code: 249, value: [16, 10, 20, ...routerIp] },
    { code: 252, value: ascii(wpad) },
    { code: 43, value: [1, 4, 0xde, 0xad, 0xbe, 0xef] },
    { code: 82, value: [1, circuitId.length, ...ascii(circuitId)] },
  ]

  for (const [level, policy] of [['diagnostic', DIAGNOSTIC_POLICY], ['high-privacy', HIGH_PRIVACY_POLICY]] as const) {
    it(`${level}: maps addresses, masks unknown values, keeps protocol parameters`, () => {
      const { payload, valueOffsets } = buildDhcpv4Ack(options)
      const frame = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, payload)
      const mapping = new SessionMapping(undefined, { seed: `dhcpv4-fail-closed-${level}` })
      const result = sanitizePacket(packetInput(frame), policy, mapping)
      expect(result.coverage.some((c) => c.protocol === 'dhcpv4' && c.status === 'covered')).toBe(true)
      const out = applyPatches(frame, result)
      const optAt = (code: number) => UDP_PAYLOAD_OFFSET + valueOffsets.get(code)!

      expect(contains(out, routerIp)).toBe(false)
      expect(contains(out, dnsIp)).toBe(false)
      expect(contains(out, ascii('198.51.100.7'))).toBe(false)
      expect(contains(out, ascii(circuitId))).toBe(false)
      expect(contains(out, [0xde, 0xad, 0xbe, 0xef])).toBe(false)
      // Classless route destination octets are masked; prefix widths stay.
      expect([...out.subarray(optAt(121) + 6, optAt(121) + 8)]).not.toEqual([10, 20])
      expect(out[optAt(121)]).toBe(0)
      expect(out[optAt(121) + 5]).toBe(16)
      expect(out[optAt(249)]).toBe(16)

      // Identity-free parameters and the option framing survive unchanged.
      expect(out[optAt(53)]).toBe(5)
      expect([...out.subarray(optAt(1), optAt(1) + 4)]).toEqual([255, 255, 255, 0])
      expect([...out.subarray(optAt(51), optAt(51) + 4)]).toEqual([0, 1, 81, 128])
      for (const opt of options) {
        expect(out[optAt(opt.code) - 2]).toBe(opt.code)
        expect(out[optAt(opt.code) - 1]).toBe(opt.value.length)
      }
    })
  }

  it('masks a classless route option whose descriptors do not fit', () => {
    const value = [24, 10, 20, 30, ...routerIp.slice(0, 2)]
    const { payload, valueOffsets } = buildDhcpv4Ack([{ code: 121, value }])
    const frame = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, payload)
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, new SessionMapping(undefined, { seed: 'dhcpv4-bad-121' }))
    const out = applyPatches(frame, result)
    const at = UDP_PAYLOAD_OFFSET + valueOffsets.get(121)!
    expect(unchangedCount(frame, out, at, value.length)).toBeLessThanOrEqual(1)
  })

  it('masks option 249 destination octets, maps its router', () => {
    const { payload, valueOffsets } = buildDhcpv4Ack([{ code: 249, value: [24, 172, 16, 99, ...routerIp] }])
    const frame = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, payload)
    const out = sanitizeFrame(frame, DIAGNOSTIC_POLICY, 'dhcpv4-249')
    const at = UDP_PAYLOAD_OFFSET + valueOffsets.get(249)!
    expect(out[at]).toBe(24)
    expect(unchangedCount(frame, out, at + 1, 3)).toBeLessThanOrEqual(1)
    expect(contains(out, routerIp)).toBe(false)
  })
})

describe('DHCPv4 bytes outside parsed options are never exported unexamined', () => {
  const secret = (s: string) => ascii(s)

  it('masks the value of a truncated last option', () => {
    // Option 12 declares 30 bytes, only 12 present, no END.
    const options = [53, 1, 5, 12, 30, ...secret('secret-host1')]
    const frame = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, buildDhcpv4Raw({ options }))
    expect(contains(sanitizeFrame(frame, DIAGNOSTIC_POLICY, 'v4-trunc'), secret('secret-host1'))).toBe(false)
  })

  it('masks bytes after the END option', () => {
    const options = [53, 1, 5, 255, ...secret('secret-after')]
    const frame = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, buildDhcpv4Raw({ options }))
    expect(contains(sanitizeFrame(frame, DIAGNOSTIC_POLICY, 'v4-after-end'), secret('secret-after'))).toBe(false)
  })

  it('masks leftovers after the sname/file terminator', () => {
    const frame = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, buildDhcpv4Raw({
      sname: [...secret('srv'), 0, ...secret('secret-tail')],
      file: [...secret('boot.bin'), 0, ...secret('secret-file')],
      options: [53, 1, 5, 255],
    }))
    const out = sanitizeFrame(frame, DIAGNOSTIC_POLICY, 'v4-tails')
    expect(contains(out, secret('secret-tail'))).toBe(false)
    expect(contains(out, secret('secret-file'))).toBe(false)
  })

  it.each([[1, 'file'], [2, 'sname'], [3, 'both']] as const)('masks an overloaded field (option 52 = %i, %s)', (overload) => {
    const carried = [12, 12, ...secret('secret-host2'), 255]
    const frame = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, buildDhcpv4Raw({
      sname: overload & 2 ? carried : [],
      file: overload & 1 ? [3, 4, 10, 0, 0, 1, ...carried] : [],
      options: [53, 1, 5, 52, 1, overload, 255],
    }))
    expect(contains(sanitizeFrame(frame, DIAGNOSTIC_POLICY, `v4-overload-${overload}`), secret('secret-host2'))).toBe(false)
  })

  it('masks non-Ethernet chaddr and the padding after an Ethernet MAC', () => {
    const longHw = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, buildDhcpv4Raw({
      hlen: 8, chaddr: [0xc0, 0xff, 0xee, 0x12, 0x34, 0x56, 0x78, 0x9a], options: [53, 1, 5, 255],
    }))
    expect(contains(sanitizeFrame(longHw, DIAGNOSTIC_POLICY, 'v4-chaddr8'), [0xc0, 0xff, 0xee, 0x12, 0x34])).toBe(false)
    const padded = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, buildDhcpv4Raw({
      chaddr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, ...secret('padSECRET')], options: [53, 1, 5, 255],
    }))
    expect(contains(sanitizeFrame(padded, DIAGNOSTIC_POLICY, 'v4-chaddr-pad'), secret('padSECRET'))).toBe(false)
  })

  it('masks client-id bytes beyond the Ethernet MAC', () => {
    const options = [53, 1, 5, 61, 10, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, ...secret('XYZ'), 255]
    const frame = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, buildDhcpv4Raw({ options }))
    const out = sanitizeFrame(frame, DIAGNOSTIC_POLICY, 'v4-client-id-long')
    expect(contains(out, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55])).toBe(false)
    expect(contains(out, secret('XYZ'))).toBe(false)
  })

  it('masks a malformed wire-encoded FQDN and bytes after its root label', () => {
    // E flag set; first label claims 70 bytes (invalid, > 63 and past the end).
    const bad = [81, 3 + 1 + 11, 0x04, 0, 0, 70, ...secret('secretfqdn1')]
    const tail = [81, 3 + 6 + 6, 0x04, 0, 0, 4, ...secret('host'), 0, ...secret('secret')]
    for (const [label, opt] of [['bad', bad], ['tail', tail]] as const) {
      const frame = buildEthIpUdp([192, 0, 2, 67], [192, 0, 2, 50], 67, 68, buildDhcpv4Raw({ options: [53, 1, 5, ...opt, 255] }))
      const out = sanitizeFrame(frame, DIAGNOSTIC_POLICY, `v4-fqdn-${label}`)
      expect(contains(out, secret('secretfqdn1'))).toBe(false)
      expect(contains(out, secret('secret'))).toBe(false)
    }
  })
})

describe('DHCPv6 fail-closed options', () => {
  const dnsServer = ipv6('2001:db8:53::53')
  const assigned = ipv6('2001:db8:10::5')
  const delegated = ipv6('2001:db8:abcd::')
  const searchDomain = 'corp.example'
  const statusText = 'Success host-secret'
  const vendorClass = ascii('VendorX-Phone')

  function buildReply(): Uint8Array {
    const iaAddr = [...assigned, 0, 0, 14, 16, 0, 0, 28, 32, ...dhcpv6Option(13, [0, 0, ...ascii('Assigned to dispatcher-pc')])]
    const iaPrefix = [0, 0, 14, 16, 0, 0, 28, 32, 48, ...delegated]
    return new Uint8Array([
      7, 0x12, 0x34, 0x56, // REPLY + transaction id
      ...dhcpv6Option(1, [0, 3, 0, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
      ...dhcpv6Option(3, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, ...dhcpv6Option(5, iaAddr)]),
      ...dhcpv6Option(25, [0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, ...dhcpv6Option(26, iaPrefix)]),
      ...dhcpv6Option(23, dnsServer),
      ...dhcpv6Option(24, dnsName(searchDomain)),
      ...dhcpv6Option(16, [0, 0, 0x30, 0x39, 0, vendorClass.length, ...vendorClass]),
      ...dhcpv6Option(13, [0, 0, ...ascii(statusText)]),
      ...dhcpv6Option(8, [0, 100]),
    ])
  }

  it('maps address lists and domains, masks vendor/status/prefix values', () => {
    const payload = buildReply()
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 50], 547, 546, payload)
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, new SessionMapping(undefined, { seed: 'dhcpv6-fail-closed' }))
    expect(result.coverage.some((c) => c.protocol === 'dhcpv6' && c.status === 'covered')).toBe(true)
    const out = applyPatches(frame, result)
    expect(contains(out, dnsServer)).toBe(false)
    expect(contains(out, assigned)).toBe(false)
    expect(contains(out, delegated.slice(0, 6))).toBe(false)
    expect(contains(out, ascii('corp'))).toBe(false)
    expect(contains(out, ascii('example'))).toBe(false)
    expect(contains(out, vendorClass)).toBe(false)
    expect(contains(out, ascii('host-secret'))).toBe(false)
    expect(contains(out, ascii('dispatcher-pc'))).toBe(false)
    expect(contains(out, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55])).toBe(false)
    // Elapsed time (identity-free) is untouched.
    expect(contains(out, dhcpv6Option(8, [0, 100]))).toBe(true)
    expect(out.length).toBe(frame.length)
  })

  it('sanitizes relay link/peer addresses, interface-id and the relayed message', () => {
    const linkAddress = ipv6('2001:db8:1::1')
    const peerAddress = ipv6('fe80::1234')
    const interfaceId = ascii('ge-0/0/1-floor3')
    const clientMac = [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
    const inner = [1, 0x01, 0x02, 0x03, ...dhcpv6Option(1, [0, 3, 0, 1, ...clientMac])] // SOLICIT
    const relay = new Uint8Array([
      12, 0, ...linkAddress, ...peerAddress,
      ...dhcpv6Option(18, interfaceId),
      ...dhcpv6Option(9, inner),
    ])
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 547, 547, relay)
    const result = sanitizePacket(packetInput(frame), DIAGNOSTIC_POLICY, new SessionMapping(undefined, { seed: 'dhcpv6-relay' }))
    const out = applyPatches(frame, result)
    expect(contains(out, linkAddress)).toBe(false)
    expect(contains(out, peerAddress)).toBe(false)
    expect(contains(out, interfaceId)).toBe(false)
    expect(contains(out, clientMac)).toBe(false)
    expect(out[UDP_PAYLOAD_OFFSET]).toBe(12)
  })

  it('high-privacy: same address/name/vendor protection', () => {
    const payload = buildReply()
    const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 50], 547, 546, payload)
    const out = sanitizeFrame(frame, HIGH_PRIVACY_POLICY, 'dhcpv6-hp')
    for (const needle of [dnsServer, assigned, ascii('corp'), vendorClass, ascii('host-secret')]) {
      expect(contains(out, needle)).toBe(false)
    }
  })

  it('masks the IAID (often the interface MAC tail)', () => {
    const iaid = [0x33, 0x44, 0x55, 0x66]
    const payload = new Uint8Array([1, 0, 0, 1, ...dhcpv6Option(3, [...iaid, 0, 0, 0, 0, 0, 0, 0, 0])])
    const frame = buildEthIpUdp([192, 0, 2, 50], [192, 0, 2, 1], 546, 547, payload)
    const out = sanitizeFrame(frame, DIAGNOSTIC_POLICY, 'dhcpv6-iaid')
    expect(unchangedCount(frame, out, UDP_PAYLOAD_OFFSET + 8, 4)).toBeLessThanOrEqual(1)
  })

  it('maps the DUID-LLT MAC and masks its fixed generation time', () => {
    const time = [0x2a, 0xbc, 0xde, 0xf0]
    const mac = [0x00, 0x99, 0x88, 0x77, 0x66, 0x55]
    const payload = new Uint8Array([1, 0, 0, 1, ...dhcpv6Option(1, [0, 1, 0, 1, ...time, ...mac])])
    const frame = buildEthIpUdp([192, 0, 2, 50], [192, 0, 2, 1], 546, 547, payload)
    const out = sanitizeFrame(frame, DIAGNOSTIC_POLICY, 'dhcpv6-duid-llt')
    expect(contains(out, mac)).toBe(false)
    expect(unchangedCount(frame, out, UDP_PAYLOAD_OFFSET + 4 + 4 + 4, 4)).toBeLessThanOrEqual(1)
    expect([...out.subarray(UDP_PAYLOAD_OFFSET + 8, UDP_PAYLOAD_OFFSET + 12)]).toEqual([0, 1, 0, 1])
  })

  it('masks short IA/IAADDR structures, a malformed FQDN and trailing bytes', () => {
    const shortIaAddr = dhcpv6Option(3, [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, ...dhcpv6Option(5, ipv6('2001:db8:77::1').slice(0, 10))])
    const shortIa = dhcpv6Option(4, [0xaa, 0xbb])
    const badFqdn = dhcpv6Option(39, [0, 70, ...ascii('secretfqdn6')])
    const payload = new Uint8Array([1, 0, 0, 1, ...shortIaAddr, ...shortIa, ...badFqdn, 0xde, 0xad, 0xbe])
    const frame = buildEthIpUdp([192, 0, 2, 50], [192, 0, 2, 1], 546, 547, payload)
    const out = sanitizeFrame(frame, DIAGNOSTIC_POLICY, 'dhcpv6-short')
    expect(contains(out, ipv6('2001:db8:77::1').slice(0, 8))).toBe(false)
    expect(contains(out, [0xaa, 0xbb])).toBe(false)
    expect(contains(out, ascii('secretfqdn6'))).toBe(false)
    expect(unchangedCount(frame, out, frame.length - 3, 3)).toBeLessThanOrEqual(1)
  })

  it('masks a relayed message that is too short or nested beyond the depth limit', () => {
    const secret = ascii('relay-secret')
    // Valid outer relay whose option 9 holds a relay-reply shorter than the 34-byte relay header.
    const shortRelay = new Uint8Array([
      12, 0, ...ipv6('2001:db8:1::1'), ...ipv6('2001:db8:2::2'), ...dhcpv6Option(9, [13, 0, ...secret]),
    ])
    let nested: number[] = [1, 0, 0, 1, ...dhcpv6Option(16, secret)]
    for (let i = 0; i < 10; i++) nested = [12, i, ...ipv6('2001:db8:1::1'), ...ipv6('2001:db8:2::2'), ...dhcpv6Option(9, nested)]
    for (const [label, payload] of [['short', shortRelay], ['deep', new Uint8Array(nested)]] as const) {
      const frame = buildEthIpUdp([192, 0, 2, 1], [192, 0, 2, 2], 547, 547, payload)
      expect(contains(sanitizeFrame(frame, DIAGNOSTIC_POLICY, `dhcpv6-relay-${label}`), secret)).toBe(false)
    }
  })
})
