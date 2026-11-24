/**
 * DHCPv4/v6 sanitizer — replaces client identifiers, hostnames, and IP addresses
 * in DHCP messages with length-preserving pseudonyms (step 5).
 *
 * Preserves: message type, option codes, lease/state structure, transaction IDs.
 */

import { PatchCollector } from './PatchCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import { ipv6Bytes16ToText, ipv6TextToBytes16 } from './ipv6Wire'

// DHCPv4 option codes with sensitive data
const OPT_HOSTNAME = 12
const OPT_DOMAIN_NAME = 15
const OPT_ROUTER = 3
const OPT_DNS = 6
const OPT_REQUESTED_IP = 50
const OPT_SERVER_ID = 54
const OPT_CLIENT_ID = 61
const OPT_FQDN = 81
const OPT_END = 255
const OPT_PAD = 0

/**
 * Sanitize a DHCPv4 message. Expects buffer starting at UDP payload.
 * DHCPv4 header: 236 fixed bytes + 4-byte magic cookie + options.
 */
export function sanitizeDhcpv4(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): boolean {
  if (length < 240) return false // 236 header + 4 magic

  // chaddr (client hardware address) at offset 28, 16 bytes (only first 6 for Ethernet)
  const hlen = buffer[offset + 2]!
  if (hlen === 6 && offset + 28 + 6 <= offset + length) {
    const mac = Array.from(buffer.slice(offset + 28, offset + 28 + 6))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':')
    intents?.recordEntityReplacement(packetIndex, offset + 28, 'mac', mac, 6)
    collector.addDeferred(offset + 28, 6, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('mac', mac)
      return new Uint8Array(mapped.split(':').map((s) => parseInt(s, 16)))
    })
  }

  // ciaddr / yiaddr / siaddr / giaddr
  patchIpv4Field(buffer, offset + 12, collector, mapping, intents, packetIndex)
  patchIpv4Field(buffer, offset + 16, collector, mapping, intents, packetIndex)
  patchIpv4Field(buffer, offset + 20, collector, mapping, intents, packetIndex)
  patchIpv4Field(buffer, offset + 24, collector, mapping, intents, packetIndex)

  // sname (server host name) at offset 44, 64 bytes — zero-terminated ASCII
  sanitizeFixedString(buffer, offset + 44, 64, collector, mapping, intents, packetIndex)
  // file (boot file name) at offset 108, 128 bytes
  sanitizeFixedString(buffer, offset + 108, 128, collector, mapping, intents, packetIndex)

  // Options start at offset 240
  let pos = offset + 240
  const end = offset + length

  while (pos < end) {
    const opt = buffer[pos]!
    if (opt === OPT_END) break
    if (opt === OPT_PAD) {
      pos++
      continue
    }
    if (pos + 1 >= end) break
    const optLen = buffer[pos + 1]!
    if (pos + 2 + optLen > end) break

    const dataOffset = pos + 2

    switch (opt) {
      case OPT_HOSTNAME:
      case OPT_DOMAIN_NAME:
        sanitizeAsciiOption(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex)
        break
      case OPT_ROUTER:
      case OPT_DNS:
        sanitizeIpv4List(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex)
        break
      case OPT_REQUESTED_IP:
      case OPT_SERVER_ID:
        if (optLen === 4) {
          patchIpv4Field(buffer, dataOffset, collector, mapping, intents, packetIndex)
        }
        break
      case OPT_CLIENT_ID:
        if (optLen >= 7 && buffer[dataOffset]! === 1) {
          // Hardware type 1 (Ethernet) — 6-byte MAC follows
          const cMac = Array.from(buffer.slice(dataOffset + 1, dataOffset + 7))
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(':')
          intents?.recordEntityReplacement(packetIndex, dataOffset + 1, 'mac', cMac, 6)
          collector.addDeferred(dataOffset + 1, 6, ({ mapping: liveMapping }) => {
            const cMapped = liveMapping.map('mac', cMac)
            return new Uint8Array(cMapped.split(':').map((s) => parseInt(s, 16)))
          })
        } else if (optLen > 0) {
          // Opaque / non-Ethernet client-id — mask in-place, keep option framing.
          const fill = createProtocolNeutralMaskFill({
            length: optLen,
            packetIndex,
            offset: dataOffset,
            domain: 'dhcpv4-client-id',
          })
          collector.maskRange(dataOffset, fill)
          intents?.recordMaskRange(packetIndex, dataOffset, optLen, 'dhcp-client-id', 'dhcpv4')
        }
        break
      case OPT_FQDN:
        if (optLen > 3) {
          // RFC 4702 flags byte, bit 0x04 ("E"): domain name is DNS wire-encoded
          // (length-prefixed labels) rather than a plain ASCII string.
          const flags = buffer[dataOffset]!
          if (flags & 0x04) {
            sanitizeDnsEncodedName(
              buffer, dataOffset + 3, optLen - 3, collector, mapping, intents, packetIndex,
            )
          } else {
            sanitizeAsciiOption(
              buffer, dataOffset + 3, optLen - 3, collector, mapping, intents, packetIndex,
            )
          }
        }
        break
    }

    pos += 2 + optLen
  }

  return true
}

/**
 * Sanitize a DHCPv6 message. Simpler structure with TLV options.
 */
export function sanitizeDhcpv6(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): boolean {
  if (length < 4) return false // msg-type (1) + transaction-id (3)

  let pos = offset + 4
  const end = offset + length

  while (pos + 4 <= end) {
    const optCode = (buffer[pos]! << 8) | buffer[pos + 1]!
    const optLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const dataOffset = pos + 4
    if (dataOffset + optLen > end) break

    switch (optCode) {
      case 1: // Client Identifier (DUID)
      case 2: // Server Identifier (DUID)
        sanitizeDuid(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex)
        break
      case 3: // IA_NA: IAID(4) + T1(4) + T2(4) + sub-options
        sanitizeIaOption(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex, 12)
        break
      case 4: // IA_TA: IAID(4) + sub-options
        sanitizeIaOption(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex, 4)
        break
      case 5: // IAADDR (standalone — uncommon but legal)
        sanitizeIaAddr(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex)
        break
      case 39: // FQDN — RFC 4704: always DNS wire-encoded, never a plain ASCII string.
        if (optLen > 1) {
          sanitizeDnsEncodedName(
            buffer, dataOffset + 1, optLen - 1, collector, mapping, intents, packetIndex,
          )
        }
        break
    }

    pos = dataOffset + optLen
  }

  return true
}

function sanitizeIaOption(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  headerLen: number,
): void {
  if (length < headerLen) return
  let pos = offset + headerLen
  const end = offset + length
  while (pos + 4 <= end) {
    const subCode = (buffer[pos]! << 8) | buffer[pos + 1]!
    const subLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const subData = pos + 4
    if (subData + subLen > end) break
    if (subCode === 5) {
      sanitizeIaAddr(buffer, subData, subLen, collector, mapping, intents, packetIndex)
    }
    pos = subData + subLen
  }
}

function sanitizeIaAddr(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  // IAADDR: IPv6 address (16) + preferred (4) + valid (4) + options
  if (length < 16) return
  const ip = ipv6Bytes16ToText(buffer, offset)
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv6', ip, 16)
  collector.addDeferred(offset, 16, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.map('ipv6', ip)
    return ipv6TextToBytes16(mapped)
  })
}

function sanitizeDuid(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (length < 2) return
  const duidType = (buffer[offset]! << 8) | buffer[offset + 1]!
  // DUID-LLT (1) or DUID-LL (3) contain hardware address at the end
  if ((duidType === 1 && length >= 10) || (duidType === 3 && length >= 6)) {
    const macStart = duidType === 1 ? offset + 8 : offset + 4
    const macLen = duidType === 1 ? length - 8 : length - 4
    if (macLen === 6) {
      const mac = Array.from(buffer.slice(macStart, macStart + 6))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(':')
      intents?.recordEntityReplacement(packetIndex, macStart, 'mac', mac, 6)
      collector.addDeferred(macStart, 6, ({ mapping: liveMapping }) => {
        const mapped = liveMapping.map('mac', mac)
        return new Uint8Array(mapped.split(':').map((s) => parseInt(s, 16)))
      })
      return
    }
  }
  // Opaque DUID — mask link-layer/id bytes after type, keep DUID type.
  if (length > 2) {
    const fill = createProtocolNeutralMaskFill({
      length: length - 2,
      packetIndex,
      offset: offset + 2,
      domain: 'dhcpv6-duid',
    })
    collector.maskRange(offset + 2, fill)
    intents?.recordMaskRange(packetIndex, offset + 2, length - 2, 'dhcp-duid', 'dhcpv6')
  }
}

function patchIpv4Field(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): void {
  const ip = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`
  if (ip === '0.0.0.0') return
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', ip, 4)
  collector.addDeferred(offset, 4, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.map('ipv4', ip)
    return new Uint8Array(mapped.split('.').map(Number))
  })
}

function sanitizeIpv4List(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  for (let i = 0; i + 4 <= length; i += 4) {
    patchIpv4Field(buffer, offset + i, collector, mapping, intents, packetIndex)
  }
}

function sanitizeFixedString(
  buffer: Uint8Array,
  offset: number,
  maxLen: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): void {
  let len = 0
  for (let i = 0; i < maxLen; i++) {
    if (buffer[offset + i] === 0) break
    len++
  }
  if (len === 0) return
  const str = String.fromCharCode(...buffer.slice(offset, offset + len))
  intents?.recordEntityReplacement(packetIndex, offset, 'hostname', str, len)
  collector.addDeferred(offset, len, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.map('hostname', str)
    const patchBytes = new Uint8Array(len)
    for (let i = 0; i < len; i++) {
      patchBytes[i] = i < mapped.length ? mapped.charCodeAt(i) : 0x2d
    }
    return patchBytes
  })
}

function sanitizeAsciiOption(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): void {
  if (length === 0) return
  const str = String.fromCharCode(...buffer.slice(offset, offset + length))
  intents?.recordEntityReplacement(packetIndex, offset, 'hostname', str, length)
  collector.addDeferred(offset, length, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.map('hostname', str)
    const patchBytes = new Uint8Array(length)
    for (let i = 0; i < length; i++) {
      patchBytes[i] = i < mapped.length ? mapped.charCodeAt(i) : 0x2d
    }
    return patchBytes
  })
}

/**
 * DNS wire-encoded domain name: a sequence of [1-byte length][label], terminated by a
 * zero-length root label — never dotted ASCII text, and never using compression pointers in
 * this context (RFC 4704 explicitly forbids them for the DHCPv6 Client FQDN option; DHCPv4's
 * FQDN option, RFC 4702, has no compression either). Treating this as one opaque ASCII string
 * (as `sanitizeAsciiOption` does) corrupts the length-prefix bytes themselves, producing a
 * structurally invalid domain name — confirmed against the local private regression capture.
 */
function sanitizeDnsEncodedName(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): void {
  const end = offset + length
  let pos = offset
  while (pos < end) {
    const labelLen = buffer[pos]!
    if (labelLen === 0) break // root terminator — nothing to patch
    const labelStart = pos + 1
    const labelEnd = labelStart + labelLen
    if (labelEnd > end) return // malformed framing in the original — leave untouched, don't guess
    const label = String.fromCharCode(...buffer.slice(labelStart, labelEnd))
    intents?.recordEntityReplacement(packetIndex, labelStart, 'hostname', label, labelLen)
    collector.addDeferred(labelStart, labelLen, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('hostname', label)
      const patchBytes = new Uint8Array(labelLen)
      for (let i = 0; i < labelLen; i++) {
        patchBytes[i] = i < mapped.length ? mapped.charCodeAt(i) : 0x2d
      }
      return patchBytes
    })
    pos = labelEnd
  }
}
