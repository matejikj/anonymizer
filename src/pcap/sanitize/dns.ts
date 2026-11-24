/**
 * DNS/mDNS sanitizer — replaces domain names and IP addresses in DNS messages
 * with length-preserving pseudonyms (step 5).
 *
 * Preserves: transaction ID, flags, RCODE, QTYPE/QCLASS, TTL, RR counts.
 * Handles: QNAME, A/AAAA/PTR/CNAME/MX/NS/SOA/SRV; unknown RDATA masked in-place.
 */

import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { PatchCollector } from './PatchCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import { ipv6Bytes16ToText, ipv6TextToBytes16 } from './ipv6Wire'
import { deferredBinaryMapMeta, deferredTextMapMeta } from './deferredMapMeta.ts'
import { maskRangeDeferredProtocolNeutral } from './deferredMaskMeta.ts'

const TYPE_A = 1
const TYPE_NS = 2
const TYPE_CNAME = 5
const TYPE_SOA = 6
const TYPE_PTR = 12
const TYPE_MX = 15
const TYPE_AAAA = 28
const TYPE_SRV = 33
const TYPE_TXT = 16

export function sanitizeDns(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): boolean {
  if (length < 12) return false

  const view = new DataView(buffer.buffer, buffer.byteOffset + offset, length)
  const qdCount = view.getUint16(4)
  const anCount = view.getUint16(6)
  const nsCount = view.getUint16(8)
  const arCount = view.getUint16(10)

  let pos = 12
  const patchedLabelStarts = new Set<number>()

  for (let i = 0; i < qdCount && pos < length; i++) {
    pos = sanitizeName(
      buffer, offset, pos, length, collector, mapping, intents, packetIndex, patchedLabelStarts,
    )
    if (pos < 0) return false
    pos += 4 // QTYPE + QCLASS
  }

  const totalRR = anCount + nsCount + arCount
  for (let i = 0; i < totalRR && pos < length; i++) {
    pos = sanitizeResourceRecord(
      buffer, offset, pos, length, collector, mapping, intents, packetIndex, patchedLabelStarts,
    )
    if (pos < 0) return false
  }

  return true
}

function sanitizeName(
  buffer: Uint8Array,
  baseOffset: number,
  pos: number,
  maxLen: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  patchedLabelStarts: Set<number>,
): number {
  const labels: { offset: number; length: number; text: string }[] = []
  let cur = pos
  let jumped = false
  let jumpReturn = -1
  let depth = 0
  const nameStartAbs = baseOffset + pos

  while (cur < maxLen && depth < 64) {
    const labelLen = buffer[baseOffset + cur]!
    if (labelLen === 0) {
      if (!jumped) pos = cur + 1
      break
    }
    if ((labelLen & 0xc0) === 0xc0) {
      if (cur + 1 >= maxLen) return -1
      const ptrOffset = ((labelLen & 0x3f) << 8) | buffer[baseOffset + cur + 1]!
      if (!jumped) {
        jumpReturn = cur + 2
        pos = jumpReturn
      }
      cur = ptrOffset
      jumped = true
      depth++
      continue
    }
    if (cur + 1 + labelLen > maxLen) return -1
    const text = String.fromCharCode(
      ...buffer.slice(baseOffset + cur + 1, baseOffset + cur + 1 + labelLen),
    )
    labels.push({ offset: cur, length: labelLen, text })
    cur += 1 + labelLen
    depth++
  }

  if (labels.length > 0) {
    const fullName = labels.map((l) => l.text).join('.')
    const firstAbs = baseOffset + labels[0]!.offset + 1
    if (intents && !patchedLabelStarts.has(firstAbs)) {
      intents.recordEntityReplacement(
        packetIndex,
        nameStartAbs,
        'hostname',
        fullName,
        Math.max(1, fullName.length),
      )
    }
    // RFC 6763 DNS-SD: <Instance>.<Service>.<Domain>, where <Service> is one or more
    // underscore-prefixed labels (_http._tcp, _csco-sb-vsdp._mdns._udp, ...) immediately
    // before the final domain label. These are protocol/service identifiers, not personal
    // identities — pseudonymizing them destroys exactly the kind of structural information
    // (e.g. "this is an mDNS Cisco VSDP announcement") this tool otherwise tries to keep
    // legible. Only the leading instance-name label(s) get mapped.
    const exemptServiceType = new Array<boolean>(labels.length).fill(false)
    for (let i = labels.length - 2; i >= 0; i--) {
      if (!labels[i]!.text.startsWith('_')) break
      exemptServiceType[i] = true
    }
    // PF-06: defer per-label. Each label independently re-resolves the same hostname (cheap
    // and consistent thanks to the memoized alias lookup) and takes its own split index —
    // this keeps each label's patch reservation at its own correct offset, unlike the
    // (unrelated, already-fixed) discovery intent which records only the whole-name offset.
    for (let i = 0; i < labels.length; i++) {
      if (exemptServiceType[i]) continue
      const label = labels[i]!
      const abs = baseOffset + label.offset + 1
      if (patchedLabelStarts.has(abs)) continue
      const labelIndex = i
      const labelLength = label.length
      try {
        const hostnameCanon = canonicalizeIdentity('hostname', fullName) ?? fullName
        collector.addDeferred(abs, labelLength, ({ mapping: liveMapping }) => {
          const mappedLabels = liveMapping.map('hostname', fullName).split('.')
          if (labelIndex >= mappedLabels.length) return null
          const replacement = mappedLabels[labelIndex]!
          const patchBytes = new Uint8Array(labelLength)
          for (let j = 0; j < labelLength; j++) {
            patchBytes[j] = j < replacement.length ? replacement.charCodeAt(j) : 0x2d
          }
          return patchBytes
        }, deferredTextMapMeta('dns', packetIndex, 'hostname', label.text, labelLength, {
          canonical: hostnameCanon,
        }))
      } catch { /* overlap */ }
      patchedLabelStarts.add(abs)
    }
  }

  return jumped ? jumpReturn! : pos
}

function sanitizeResourceRecord(
  buffer: Uint8Array,
  baseOffset: number,
  pos: number,
  maxLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  patchedLabelStarts: Set<number>,
): number {
  pos = sanitizeName(
    buffer, baseOffset, pos, maxLen, collector, mapping, intents, packetIndex, patchedLabelStarts,
  )
  if (pos < 0) return -1

  if (pos + 10 > maxLen) return -1
  const view = new DataView(buffer.buffer, buffer.byteOffset + baseOffset, maxLen)
  const rrType = view.getUint16(pos)
  pos += 4 // TYPE + CLASS
  pos += 4 // TTL
  const rdLength = view.getUint16(pos)
  pos += 2
  const rdStart = pos

  if (pos + rdLength > maxLen) return -1

  switch (rrType) {
    case TYPE_A:
      if (rdLength === 4) {
        const ip = `${buffer[baseOffset + rdStart]}.${buffer[baseOffset + rdStart + 1]}.${buffer[baseOffset + rdStart + 2]}.${buffer[baseOffset + rdStart + 3]}`
        intents?.recordEntityReplacement(packetIndex, baseOffset + rdStart, 'ipv4', ip, 4)
        const ipv4Canon = canonicalizeIdentity('ipv4', ip) ?? ip
        collector.addDeferred(baseOffset + rdStart, 4, ({ mapping: liveMapping }) => {
          const mapped = liveMapping.map('ipv4', ip)
          return new Uint8Array(mapped.split('.').map(Number))
        }, deferredBinaryMapMeta('dns', packetIndex, 'ipv4', ip, { canonical: ipv4Canon }))
      }
      break
    case TYPE_AAAA:
      if (rdLength === 16) {
        const ip = ipv6Bytes16ToText(buffer, baseOffset + rdStart)
        intents?.recordEntityReplacement(packetIndex, baseOffset + rdStart, 'ipv6', ip, 16)
        const ipv6Canon = canonicalizeIdentity('ipv6', ip) ?? ip
        collector.addDeferred(baseOffset + rdStart, 16, ({ mapping: liveMapping }) => {
          const mapped = liveMapping.map('ipv6', ip)
          return ipv6TextToBytes16(mapped)
        }, deferredBinaryMapMeta('dns', packetIndex, 'ipv6', ip, { canonical: ipv6Canon }))
      }
      break
    case TYPE_CNAME:
    case TYPE_PTR:
    case TYPE_NS:
      sanitizeName(
        buffer, baseOffset, rdStart, maxLen, collector, mapping, intents, packetIndex, patchedLabelStarts,
      )
      break
    case TYPE_MX:
      if (rdLength >= 4) {
        sanitizeName(
          buffer, baseOffset, rdStart + 2, maxLen, collector, mapping, intents, packetIndex, patchedLabelStarts,
        )
      }
      break
    case TYPE_SOA: {
      let soaPos = sanitizeName(
        buffer, baseOffset, rdStart, maxLen, collector, mapping, intents, packetIndex, patchedLabelStarts,
      )
      if (soaPos >= 0) {
        sanitizeName(
          buffer, baseOffset, soaPos, maxLen, collector, mapping, intents, packetIndex, patchedLabelStarts,
        )
      }
      break
    }
    case TYPE_SRV:
      if (rdLength >= 8) {
        sanitizeName(
          buffer, baseOffset, rdStart + 6, maxLen, collector, mapping, intents, packetIndex, patchedLabelStarts,
        )
      }
      break
    case TYPE_TXT:
      // Previously fell to the `default` full-span mask-in-place below, which — unlike every
      // other RR type here — does NOT preserve the RDATA's own internal framing: TXT is a
      // sequence of [1-byte length][string] sub-records, and overwriting that whole span with
      // random bytes almost always turns some byte into a bogus sub-record length that
      // overruns the record, producing a genuinely malformed packet (confirmed against the
      // local private regression capture — Wireshark/tshark reports "Malformed Packet" on the result).
      if (rdLength > 0) sanitizeTxtRecord(buffer, baseOffset, rdStart, rdLength, collector, mapping, intents, packetIndex)
      break
    default:
      if (rdLength > 0) {
        const domain = `dns-rdata:${rrType}`
        const abs = baseOffset + rdStart
        try {
          maskRangeDeferredProtocolNeutral(
            collector,
            abs,
            rdLength,
            packetIndex,
            domain,
            'dns',
            `dns-unknown-rdata-${rrType}`,
          )
          intents?.recordMaskRange(packetIndex, abs, rdLength, `dns-unknown-rdata-${rrType}`, 'dns')
        } catch {
          /* overlap */
        }
      }
      break
  }

  return rdStart + rdLength
}

const IPV4_OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const IPV4_IN_TEXT = new RegExp(`\\b${IPV4_OCTET}\\.${IPV4_OCTET}\\.${IPV4_OCTET}\\.${IPV4_OCTET}\\b`)
const MAC_IN_TEXT = /\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b/
/** A bare "key=<digits>" or bare token — vendor TXT diagnostic/topology data, no identity. */
const BENIGN_TXT_VALUE = /^[a-zA-Z][\w-]*(?:=\d*)?$/
/**
 * Cisco VSDP mDNS TXT carries the access-switch's voice VLAN ID as plain digits here — this
 * is the SAME VLAN number that gets pseudonymized in the 802.1Q tag elsewhere in the capture
 * (and in CDP's Native VLAN TLV, see sanitizeCdp in engine.ts), so it must go through the same
 * VLAN mapping rather than being treated as benign diagnostic data.
 */
const VLAN_ID_KV = /^voice-vlan-id=(\d+)$/i

/** Walks a TXT RR's [1-byte length][string] sub-records, never touching the length-prefix bytes. */
function sanitizeTxtRecord(
  buffer: Uint8Array,
  baseOffset: number,
  rdStart: number,
  rdLength: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const end = rdStart + rdLength
  let pos = rdStart
  while (pos < end) {
    const strLen = buffer[baseOffset + pos]!
    const valueStart = pos + 1
    const valueEnd = valueStart + strLen
    if (valueEnd > end) {
      // Malformed sub-record framing in the original capture — fail safe: mask only what's
      // left, never write past the RR's own declared bounds.
      const remLen = end - pos
      const abs = baseOffset + pos
      try {
        maskRangeDeferredProtocolNeutral(
          collector,
          abs,
          remLen,
          packetIndex,
          'dns-txt-malformed',
          'dns',
          'dns-txt-malformed',
        )
        intents?.recordMaskRange(packetIndex, abs, remLen, 'dns-txt-malformed', 'dns')
      } catch {
        /* overlap */
      }
      return
    }
    if (strLen > 0) {
      sanitizeTxtValue(buffer, baseOffset, valueStart, strLen, collector, mapping, intents, packetIndex)
    }
    pos = valueEnd
  }
}

function sanitizeTxtValue(
  buffer: Uint8Array,
  baseOffset: number,
  valueStart: number,
  valueLen: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  let text = ''
  for (let i = 0; i < valueLen; i++) text += String.fromCharCode(buffer[baseOffset + valueStart + i]!)

  let matched = false
  const macMatch = MAC_IN_TEXT.exec(text)
  if (macMatch) {
    matched = true
    const mac = macMatch[0].toLowerCase()
    const matchOffset = baseOffset + valueStart + macMatch.index
    intents?.recordEntityReplacement(packetIndex, matchOffset, 'mac', mac, mac.length)
    collector.addDeferred(matchOffset, mac.length, ({ mapping: liveMapping }) => {
      const alias = liveMapping.aliasFor('mac', mac, { kind: 'text-ascii', byteLength: mac.length })
      return new Uint8Array(Array.from(alias, (c) => c.charCodeAt(0)))
    })
  }
  const ipMatch = IPV4_IN_TEXT.exec(text)
  if (ipMatch) {
    matched = true
    const ip = ipMatch[0]
    const matchOffset = baseOffset + valueStart + ipMatch.index
    intents?.recordEntityReplacement(packetIndex, matchOffset, 'ipv4', ip, ip.length)
    collector.addDeferred(matchOffset, ip.length, ({ mapping: liveMapping }) => {
      const alias = liveMapping.aliasFor('ipv4', ip, { kind: 'text-ascii', byteLength: ip.length })
      return new Uint8Array(Array.from(alias, (c) => c.charCodeAt(0)))
    })
  }
  if (matched) return

  const vlanMatch = VLAN_ID_KV.exec(text)
  if (vlanMatch) {
    const vlanId = vlanMatch[1]!
    const matchOffset = baseOffset + valueStart + (text.length - vlanId.length)
    intents?.recordEntityReplacement(packetIndex, matchOffset, 'vlan', vlanId, vlanId.length)
    collector.addDeferred(matchOffset, vlanId.length, ({ mapping: liveMapping }) => {
      const alias = liveMapping.aliasFor('vlan', vlanId, { kind: 'text-ascii', byteLength: vlanId.length })
      return new Uint8Array(Array.from(alias, (c) => c.charCodeAt(0)))
    })
    return
  }

  if (BENIGN_TXT_VALUE.test(text)) return // pure diagnostic/topology data (priority, cost, ...)

  const abs = baseOffset + valueStart
  try {
    maskRangeDeferredProtocolNeutral(
      collector,
      abs,
      valueLen,
      packetIndex,
      'dns-txt-value',
      'dns',
      'dns-txt-value',
    )
    intents?.recordMaskRange(packetIndex, abs, valueLen, 'dns-txt-value', 'dns')
  } catch {
    /* overlap */
  }
}
