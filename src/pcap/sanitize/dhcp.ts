/**
 * DHCPv4/v6 sanitizer — replaces client identifiers, hostnames, and IP addresses
 * in DHCP messages with length-preserving pseudonyms (step 5).
 *
 * Preserves: message type, option codes and lengths, lease/state structure, transaction IDs.
 *
 * Fail-closed per option: only options known to carry no identity are kept as-is, options with
 * a known address/name layout are mapped, and every other option value (vendor-specific,
 * relay-agent, classless route destinations, URLs, free text, …) is masked in place.
 */

import { PatchCollector } from './PatchCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import { ipv6Bytes16ToText, ipv6TextToBytes16 } from './ipv6Wire'

// DHCPv4 option codes with sensitive data
const OPT_HOSTNAME = 12
const OPT_DOMAIN_NAME = 15
const OPT_CLIENT_ID = 61
const OPT_FQDN = 81
const OPT_CLASSLESS_ROUTE = 121
const OPT_MS_CLASSLESS_ROUTE = 249
const OPT_END = 255
const OPT_PAD = 0

/** RFC 2132/3046/… parameters that never carry an identity — kept for diagnostics. */
const DHCPV4_PRESERVED_OPTIONS: ReadonlySet<number> = new Set([
  1, // subnet mask
  2, // time offset
  13, // boot file size
  19, 20, // IP forwarding, non-local source routing
  22, 23, 24, 26, 27, // reassembly size, default TTL, PMTU aging, MTU, all subnets local
  29, 30, 31, // mask discovery/supplier, router discovery
  34, 35, 36, 37, 38, 39, // trailer encapsulation, ARP timeout, Ethernet encap., TCP TTL/keepalive
  46, // NetBIOS node type
  51, 52, 53, // lease time, option overload, message type
  55, 57, 58, 59, // parameter request list, max message size, T1, T2
  80, 91, 108, 116, 145, // rapid commit, last transaction time, IPv6-only, auto-config, FORCERENEW
])

/** Options whose value is a list of IPv4 addresses (4 bytes each). */
const DHCPV4_ADDRESS_LIST_OPTIONS: ReadonlySet<number> = new Set([
  3, 4, 5, 6, 7, 8, 9, 10, 11, // router, time/name/DNS/log/cookie/LPR/impress/resource location
  16, 28, 32, 33, // swap server, broadcast address, router solicitation, static routes
  41, 42, 44, 45, 48, 49, // NIS, NTP, NetBIOS NS/DD, X font/display manager
  50, 54, 65, 68, 69, 70, 71, 72, 73, 74, 75, 76, // requested IP, server id, NIS+, mobile IP, servers
  118, 150, // subnet selection, TFTP server addresses
])

// DHCPv6 option codes (RFC 8415 and companions)
const DHCPV6_RELAY_FORW = 12
const DHCPV6_RELAY_REPL = 13
const DHCPV6_RELAY_HEADER = 34 // msg-type + hop-count + link-address + peer-address

/** Parameters with no identity content — kept for diagnostics. */
const DHCPV6_PRESERVED_OPTIONS: ReadonlySet<number> = new Set([
  6, // option request
  7, // preference
  8, // elapsed time
  14, // rapid commit
  19, // reconfigure message
  20, // reconfigure accept
  32, // information refresh time
  82, 83, // SOL_MAX_RT, INF_MAX_RT
])

/** Options whose value is a list of IPv6 addresses (16 bytes each). */
const DHCPV6_ADDRESS_LIST_OPTIONS: ReadonlySet<number> = new Set([
  12, // server unicast
  22, // SIP servers address list
  23, // DNS recursive name servers
  27, 28, // NIS, NIS+ servers
  31, // SNTP servers
  34, // BCMCS controller addresses
  40, // PANA agent
  52, // CAPWAP access controllers
])

/** Options whose value is a list of DNS wire-encoded domain names. */
const DHCPV6_DOMAIN_LIST_OPTIONS: ReadonlySet<number> = new Set([
  21, // SIP servers domain list
  24, // domain search list
  29, 30, // NIS, NIS+ domain name
  33, // BCMCS controller domain list
])

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
  if (hlen === 6) {
    const mac = Array.from(buffer.slice(offset + 28, offset + 28 + 6))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':')
    intents?.recordEntityReplacement(packetIndex, offset + 28, 'mac', mac, 6)
    collector.addDeferred(offset + 28, 6, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('mac', mac)
      return new Uint8Array(mapped.split(':').map((s) => parseInt(s, 16)))
    })
    maskIfNonZero(buffer, collector, intents, packetIndex, offset + 34, 10, 'dhcpv4', 'dhcpv4-chaddr-pad')
  } else {
    // Non-Ethernet hardware address — no mapping category for it, mask the whole field.
    maskIfNonZero(buffer, collector, intents, packetIndex, offset + 28, 16, 'dhcpv4', 'dhcpv4-chaddr')
  }

  // ciaddr / yiaddr / siaddr / giaddr
  patchIpv4Field(buffer, offset + 12, collector, mapping, intents, packetIndex)
  patchIpv4Field(buffer, offset + 16, collector, mapping, intents, packetIndex)
  patchIpv4Field(buffer, offset + 20, collector, mapping, intents, packetIndex)
  patchIpv4Field(buffer, offset + 24, collector, mapping, intents, packetIndex)

  // RFC 2132 option 52: sname/file may carry further options instead of strings. Those are
  // not parsed here — mask an overloaded field whole.
  const overload = findOptionOverload(buffer, offset + 240, offset + length)
  // sname (server host name) at offset 44, 64 bytes — zero-terminated ASCII
  if (overload & 2) maskIfNonZero(buffer, collector, intents, packetIndex, offset + 44, 64, 'dhcpv4', 'dhcpv4-sname-overload')
  else sanitizeFixedString(buffer, offset + 44, 64, collector, mapping, intents, packetIndex)
  // file (boot file name) at offset 108, 128 bytes
  if (overload & 1) maskIfNonZero(buffer, collector, intents, packetIndex, offset + 108, 128, 'dhcpv4', 'dhcpv4-file-overload')
  else sanitizeFixedString(buffer, offset + 108, 128, collector, mapping, intents, packetIndex)

  // Options start at offset 240
  let pos = offset + 240
  const end = offset + length

  while (pos < end) {
    const opt = buffer[pos]!
    if (opt === OPT_END) {
      // Anything after END is not part of the message — never export it unexamined.
      maskIfNonZero(buffer, collector, intents, packetIndex, pos + 1, end - pos - 1, 'dhcpv4', 'dhcpv4-after-end')
      break
    }
    if (opt === OPT_PAD) {
      pos++
      continue
    }
    if (pos + 1 >= end) break // a lone option code byte carries no value
    const optLen = buffer[pos + 1]!
    if (pos + 2 + optLen > end) {
      // Truncated option: its value bytes are unexamined — mask what is present.
      maskOptionValue(collector, intents, packetIndex, pos + 2, end - pos - 2, 'dhcpv4', opt)
      break
    }

    const dataOffset = pos + 2

    if (DHCPV4_PRESERVED_OPTIONS.has(opt)) {
      pos += 2 + optLen
      continue
    }
    if (DHCPV4_ADDRESS_LIST_OPTIONS.has(opt)) {
      if (optLen > 0 && optLen % 4 === 0) {
        sanitizeIpv4List(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex)
      } else {
        maskOptionValue(collector, intents, packetIndex, dataOffset, optLen, 'dhcpv4', opt)
      }
      pos += 2 + optLen
      continue
    }

    switch (opt) {
      case OPT_HOSTNAME:
      case OPT_DOMAIN_NAME:
        sanitizeAsciiOption(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex)
        break
      case OPT_CLASSLESS_ROUTE:
      case OPT_MS_CLASSLESS_ROUTE:
        sanitizeClasslessRoutes(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex)
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
          if (optLen > 7) {
            maskOptionValue(collector, intents, packetIndex, dataOffset + 7, optLen - 7, 'dhcpv4', opt)
          }
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
            if (!sanitizeDnsEncodedName(
              buffer, dataOffset + 3, optLen - 3, collector, mapping, intents, packetIndex,
            )) {
              maskOptionValue(collector, intents, packetIndex, dataOffset + 3, optLen - 3, 'dhcpv4', opt)
            }
          } else {
            sanitizeAsciiOption(
              buffer, dataOffset + 3, optLen - 3, collector, mapping, intents, packetIndex,
            )
          }
        }
        break
      default:
        // Vendor-specific, relay-agent, URL, free-text and any unknown option.
        maskOptionValue(collector, intents, packetIndex, dataOffset, optLen, 'dhcpv4', opt)
    }

    pos += 2 + optLen
  }

  return true
}

/**
 * RFC 3442 classless static routes: `width | significant destination octets | router(4)`.
 * Routers are mapped like every other address; destination prefixes are masked because a
 * truncated prefix cannot go through the host-address mapping. Unparseable → mask whole value.
 */
function sanitizeClasslessRoutes(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const end = offset + length
  const routers: number[] = []
  const destinations: Array<[number, number]> = []
  let pos = offset
  while (pos < end) {
    const width = buffer[pos]!
    const significant = Math.ceil(width / 8)
    if (width > 32 || pos + 1 + significant + 4 > end) {
      maskOptionValue(collector, intents, packetIndex, offset, length, 'dhcpv4', OPT_CLASSLESS_ROUTE)
      return
    }
    if (significant > 0) destinations.push([pos + 1, significant])
    routers.push(pos + 1 + significant)
    pos += 1 + significant + 4
  }
  for (const [destOffset, destLength] of destinations) {
    maskOptionValue(collector, intents, packetIndex, destOffset, destLength, 'dhcpv4', OPT_CLASSLESS_ROUTE)
  }
  for (const routerOffset of routers) {
    patchIpv4Field(buffer, routerOffset, collector, mapping, intents, packetIndex)
  }
}

/** Value of option 52 (1 = file, 2 = sname, 3 = both carry options), 0 when absent. */
function findOptionOverload(buffer: Uint8Array, start: number, end: number): number {
  let pos = start
  while (pos + 1 < end) {
    const opt = buffer[pos]!
    if (opt === OPT_END) break
    if (opt === OPT_PAD) {
      pos++
      continue
    }
    const optLen = buffer[pos + 1]!
    if (pos + 2 + optLen > end) break
    if (opt === 52 && optLen === 1) return buffer[pos + 2]! & 3
    pos += 2 + optLen
  }
  return 0
}

/** Masks a fixed region unless it is all zero padding (zeros carry nothing worth hiding). */
function maskIfNonZero(
  buffer: Uint8Array,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  protocol: 'dhcpv4' | 'dhcpv6',
  reason: string,
): void {
  if (length <= 0) return
  let nonZero = false
  for (let i = 0; i < length; i++) {
    if (buffer[offset + i] !== 0) {
      nonZero = true
      break
    }
  }
  if (!nonZero) return
  collector.maskRange(offset, createProtocolNeutralMaskFill({ length, packetIndex, offset, domain: reason }))
  intents?.recordMaskRange(packetIndex, offset, length, reason, protocol)
}

function maskOptionValue(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  protocol: 'dhcpv4' | 'dhcpv6',
  optionCode: number | string,
): void {
  if (length <= 0) return
  const fill = createProtocolNeutralMaskFill({
    length,
    packetIndex,
    offset,
    domain: `${protocol}-option`,
  })
  collector.maskRange(offset, fill)
  intents?.recordMaskRange(packetIndex, offset, length, `${protocol}-option-${optionCode}`, protocol)
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
  return sanitizeDhcpv6Message(buffer, offset, length, collector, mapping, intents, packetIndex, 0)
}

/** Relay messages nest a whole client/server message in option 9; bound the recursion. */
const DHCPV6_MAX_RELAY_DEPTH = 8

function sanitizeDhcpv6Message(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  depth: number,
): boolean {
  if (length < 4) return false // msg-type (1) + transaction-id (3)

  const msgType = buffer[offset]!
  const isRelay = msgType === DHCPV6_RELAY_FORW || msgType === DHCPV6_RELAY_REPL
  if (isRelay) {
    if (length < DHCPV6_RELAY_HEADER) return false
    patchIpv6Field(buffer, offset + 2, collector, intents, packetIndex) // link-address
    patchIpv6Field(buffer, offset + 18, collector, intents, packetIndex) // peer-address
  }

  let pos = offset + (isRelay ? DHCPV6_RELAY_HEADER : 4)
  const end = offset + length

  while (pos + 4 <= end) {
    const optCode = (buffer[pos]! << 8) | buffer[pos + 1]!
    const optLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const dataOffset = pos + 4
    if (dataOffset + optLen > end) {
      // Truncated option: never leave its bytes unexamined.
      maskOptionValue(collector, intents, packetIndex, dataOffset, end - dataOffset, 'dhcpv6', optCode)
      pos = end
      break
    }

    if (DHCPV6_PRESERVED_OPTIONS.has(optCode)) {
      pos = dataOffset + optLen
      continue
    }
    if (DHCPV6_ADDRESS_LIST_OPTIONS.has(optCode)) {
      if (optLen > 0 && optLen % 16 === 0) {
        for (let i = 0; i < optLen; i += 16) {
          patchIpv6Field(buffer, dataOffset + i, collector, intents, packetIndex)
        }
      } else {
        maskOptionValue(collector, intents, packetIndex, dataOffset, optLen, 'dhcpv6', optCode)
      }
      pos = dataOffset + optLen
      continue
    }
    if (DHCPV6_DOMAIN_LIST_OPTIONS.has(optCode)) {
      if (!sanitizeDnsEncodedNameList(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex)) {
        maskOptionValue(collector, intents, packetIndex, dataOffset, optLen, 'dhcpv6', optCode)
      }
      pos = dataOffset + optLen
      continue
    }

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
      case 25: // IA_PD: IAID(4) + T1(4) + T2(4) + sub-options (IAPREFIX)
        sanitizeIaOption(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex, 12)
        break
      case 5: // IAADDR (standalone — uncommon but legal)
        sanitizeIaAddr(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex)
        break
      case 9: // Relay Message — nested client/server or relay message
        if (
          depth >= DHCPV6_MAX_RELAY_DEPTH
          || !sanitizeDhcpv6Message(buffer, dataOffset, optLen, collector, mapping, intents, packetIndex, depth + 1)
        ) {
          maskOptionValue(collector, intents, packetIndex, dataOffset, optLen, 'dhcpv6', optCode)
        }
        break
      case 13: // Status Code: code(2) + free-text message
        sanitizeStatusCode(collector, intents, packetIndex, dataOffset, optLen)
        break
      case 39: // FQDN — RFC 4704: always DNS wire-encoded, never a plain ASCII string.
        if (optLen > 1 && !sanitizeDnsEncodedName(
          buffer, dataOffset + 1, optLen - 1, collector, mapping, intents, packetIndex,
        )) {
          maskOptionValue(collector, intents, packetIndex, dataOffset + 1, optLen - 1, 'dhcpv6', optCode)
        }
        break
      default:
        // Vendor class/opts, user class, interface/remote/subscriber ID and any unknown option.
        maskOptionValue(collector, intents, packetIndex, dataOffset, optLen, 'dhcpv6', optCode)
    }

    pos = dataOffset + optLen
  }
  // 1–3 trailing bytes too short for an option header.
  if (pos < end) maskOptionValue(collector, intents, packetIndex, pos, end - pos, 'dhcpv6', 'trailing')

  return true
}

function sanitizeStatusCode(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
): void {
  // Keep the numeric status for diagnostics; the message is server-defined free text.
  if (length > 2) maskOptionValue(collector, intents, packetIndex, offset + 2, length - 2, 'dhcpv6', 13)
}

function patchIpv6Field(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const ip = ipv6Bytes16ToText(buffer, offset)
  if (ip === '::') return
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv6', ip, 16)
  collector.addDeferred(offset, 16, ({ mapping: liveMapping }) => ipv6TextToBytes16(liveMapping.map('ipv6', ip)))
}

/**
 * Sequence of DNS wire-encoded names filling the whole option (RFC 1035 §3.1, no compression).
 * Returns false when the framing does not exactly fill the option — caller then masks it.
 */
function sanitizeDnsEncodedNameList(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): boolean {
  const end = offset + length
  const names: Array<[number, number]> = []
  let pos = offset
  let nameStart = offset
  while (pos < end) {
    const labelLen = buffer[pos]!
    if (labelLen === 0) {
      names.push([nameStart, pos + 1 - nameStart])
      pos += 1
      nameStart = pos
      continue
    }
    if (labelLen > 63 || pos + 1 + labelLen > end) return false
    pos += 1 + labelLen
  }
  if (nameStart !== end) return false // last name not root-terminated
  for (const [nameOffset, nameLength] of names) {
    sanitizeDnsEncodedName(buffer, nameOffset, nameLength, collector, mapping, intents, packetIndex)
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
  if (length < headerLen) {
    maskOptionValue(collector, intents, packetIndex, offset, length, 'dhcpv6', 'ia-short')
    return
  }
  // IAID: clients commonly derive it from the interface MAC (last 4 bytes) — never keep it.
  maskOptionValue(collector, intents, packetIndex, offset, 4, 'dhcpv6', 'iaid')
  sanitizeIaSubOptions(buffer, offset + headerLen, offset + length, collector, mapping, intents, packetIndex)
}

/** Sub-options of IA_NA / IA_TA / IA_PD / IAADDR, fail-closed like top-level options. */
function sanitizeIaSubOptions(
  buffer: Uint8Array,
  start: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  let pos = start
  while (pos + 4 <= end) {
    const subCode = (buffer[pos]! << 8) | buffer[pos + 1]!
    const subLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const subData = pos + 4
    if (subData + subLen > end) {
      maskOptionValue(collector, intents, packetIndex, subData, end - subData, 'dhcpv6', subCode)
      pos = end
      break
    }
    if (subCode === 5) {
      sanitizeIaAddr(buffer, subData, subLen, collector, mapping, intents, packetIndex)
    } else if (subCode === 13) {
      sanitizeStatusCode(collector, intents, packetIndex, subData, subLen)
    } else if (subCode === 26) {
      // IAPREFIX: preferred(4) + valid(4) + prefix-length(1) + prefix(16) + options.
      // A delegated prefix is not a host address — mask it, keep lifetimes and length.
      if (subLen >= 25) {
        maskOptionValue(collector, intents, packetIndex, subData + 9, 16, 'dhcpv6', subCode)
        if (subLen > 25) maskOptionValue(collector, intents, packetIndex, subData + 25, subLen - 25, 'dhcpv6', subCode)
      } else {
        maskOptionValue(collector, intents, packetIndex, subData, subLen, 'dhcpv6', subCode)
      }
    } else {
      maskOptionValue(collector, intents, packetIndex, subData, subLen, 'dhcpv6', subCode)
    }
    pos = subData + subLen
  }
  if (pos < end) maskOptionValue(collector, intents, packetIndex, pos, end - pos, 'dhcpv6', 'trailing')
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
  if (length < 16) {
    maskOptionValue(collector, intents, packetIndex, offset, length, 'dhcpv6', 5)
    return
  }
  patchIpv6Field(buffer, offset, collector, intents, packetIndex)
  if (length > 24) {
    sanitizeIaSubOptions(buffer, offset + 24, offset + length, collector, _mapping, intents, packetIndex)
  }
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
      // DUID-LLT time is fixed per device (generation time) — it would re-link the mapped MAC.
      if (duidType === 1) maskOptionValue(collector, intents, packetIndex, offset + 4, 4, 'dhcpv6', 'duid-time')
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
  // Bytes after the terminator are not part of the string but still exported — mask leftovers.
  if (len + 1 < maxLen) {
    maskIfNonZero(buffer, collector, intents, packetIndex, offset + len + 1, maxLen - len - 1, 'dhcpv4', 'dhcpv4-fixed-string-tail')
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
 * structurally invalid domain name — confirmed against the real dt.pcap capture.
 */
function sanitizeDnsEncodedName(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): boolean {
  const end = offset + length
  // Validate the whole framing before patching anything, so a caller can mask the value
  // instead without overlapping patches. Labels > 63 are compression pointers / garbage here.
  const labels: Array<[number, number]> = []
  let pos = offset
  let rootAt = -1
  while (pos < end) {
    const labelLen = buffer[pos]!
    if (labelLen === 0) {
      rootAt = pos
      break
    }
    if (labelLen > 63 || pos + 1 + labelLen > end) return false
    labels.push([pos + 1, labelLen])
    pos += 1 + labelLen
  }
  // Bytes after the root label are outside the name — never export them unexamined.
  if (rootAt >= 0 && rootAt + 1 < end) {
    const tail = rootAt + 1
    collector.maskRange(tail, createProtocolNeutralMaskFill({ length: end - tail, packetIndex, offset: tail, domain: 'dhcp-fqdn-tail' }))
    intents?.recordMaskRange(packetIndex, tail, end - tail, 'dhcp-fqdn-tail', 'dhcp')
  }
  for (const [labelStart, labelLen] of labels) {
    const label = String.fromCharCode(...buffer.slice(labelStart, labelStart + labelLen))
    intents?.recordEntityReplacement(packetIndex, labelStart, 'hostname', label, labelLen)
    collector.addDeferred(labelStart, labelLen, ({ mapping: liveMapping }) => {
      const mapped = liveMapping.map('hostname', label)
      const patchBytes = new Uint8Array(labelLen)
      for (let i = 0; i < labelLen; i++) {
        patchBytes[i] = i < mapped.length ? mapped.charCodeAt(i) : 0x2d
      }
      return patchBytes
    })
  }
  return true
}
