/**
 * T19 — LLDP / LLDP-MED (EtherType 0x88CC): chassis/port/system name map; MED location always masked.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage, SanitizationPolicy } from './types'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { maskPayloadSpan } from '../protocols/application/textproto'

export const ETHERTYPE_LLDP = 0x88cc

/** IEEE 802.1AB basic TLV types. */
const TLV_END = 0
const TLV_CHASSIS_ID = 1
const TLV_PORT_ID = 2
const TLV_TTL = 3
const TLV_PORT_DESC = 4
const TLV_SYS_NAME = 5
const TLV_SYS_DESC = 6
const TLV_SYS_CAP = 7
const TLV_MGMT_ADDR = 8
const TLV_ORG = 127

const CHASSIS_MAC = 4
const CHASSIS_NET = 5
const CHASSIS_IFNAME = 6
const CHASSIS_LOCAL = 7

const PORT_MAC = 3
const PORT_IFNAME = 5
const PORT_LOCAL = 7

/** LLDP-MED OUI 00-12-BB */
const OUI_MED = (0x00 << 16) | (0x12 << 8) | 0xbb
/** IEEE 802.1 OUI 00-80-C2 */
const OUI_8021 = (0x00 << 16) | (0x80 << 8) | 0xc2
/** IEEE 802.3 OUI 00-12-0F */
const OUI_8023 = (0x00 << 16) | (0x12 << 8) | 0x0f

const MED_NETWORK_POLICY = 2
const MED_LOCATION = 3
const MED_INV_HW = 5
const MED_INV_FW = 6
const MED_INV_SW = 7
const MED_INV_SERIAL = 8
const MED_INV_MFG = 9
const MED_INV_MODEL = 10
const MED_INV_ASSET = 11

export function sanitizeLldp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  policy: SanitizationPolicy,
): AppLayerResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset
  let sawChassis = false
  let sawPort = false
  let sawTtl = false

  while (pos + 2 <= end) {
    const hdr = (buffer[pos]! << 8) | buffer[pos + 1]!
    const type = (hdr >> 9) & 0x7f
    const tlvLen = hdr & 0x1ff
    if (pos + 2 + tlvLen > end) {
      coverage.push({ protocol: 'lldp', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('lldp-tlv-truncated')
      break
    }
    const valueOff = pos + 2
    if (type === TLV_END) {
      coverage.push({ protocol: 'lldp', offset: pos, length: 2 + tlvLen, status: 'covered' })
      pos = end
      break
    }

    switch (type) {
      case TLV_CHASSIS_ID:
        sawChassis = true
        sanitizeIdTlv(buffer, valueOff, tlvLen, collector, mapping, intents, packetIndex, 'chassis')
        coverage.push({ protocol: 'lldp', offset: pos, length: 2 + tlvLen, status: 'covered' })
        break
      case TLV_PORT_ID:
        sawPort = true
        sanitizeIdTlv(buffer, valueOff, tlvLen, collector, mapping, intents, packetIndex, 'port')
        coverage.push({ protocol: 'lldp', offset: pos, length: 2 + tlvLen, status: 'covered' })
        break
      case TLV_TTL:
      case TLV_SYS_CAP:
        sawTtl = sawTtl || type === TLV_TTL
        coverage.push({ protocol: 'lldp', offset: pos, length: 2 + tlvLen, status: 'covered' })
        break
      case TLV_SYS_NAME:
        mapAsciiHostname(buffer, valueOff, tlvLen, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'lldp', offset: pos, length: 2 + tlvLen, status: 'covered' })
        break
      case TLV_PORT_DESC:
      case TLV_SYS_DESC:
        // T63 — until free-text allowlist (T69), mask descriptions in both levels.
        sanitizeDescription(buffer, valueOff, tlvLen, collector, mapping, intents, packetIndex, policy)
        coverage.push({
          protocol: 'lldp',
          offset: pos,
          length: 2 + tlvLen,
          status: 'redacted',
        })
        break
      case TLV_MGMT_ADDR:
        sanitizeMgmtAddr(buffer, valueOff, tlvLen, collector, mapping, intents, packetIndex)
        coverage.push({ protocol: 'lldp', offset: pos, length: 2 + tlvLen, status: 'covered' })
        break
      case TLV_ORG:
        sanitizeOrgTlv(buffer, valueOff, tlvLen, collector, mapping, intents, packetIndex, policy, coverage, pos)
        break
      default:
        maskSpan(collector, intents, packetIndex, valueOff, tlvLen, 'lldp-unknown-tlv')
        coverage.push({ protocol: 'lldp', offset: pos, length: 2 + tlvLen, status: 'redacted' })
    }
    pos += 2 + tlvLen
  }

  if (!sawChassis || !sawPort || !sawTtl) {
    issues.push('lldp-missing-mandatory')
  }
  if (coverage.length === 0) {
    coverage.push({ protocol: 'lldp', offset, length, status: 'malformed' })
  }
  return { coverage, issues }
}

function sanitizeIdTlv(
  buffer: Uint8Array,
  valueOff: number,
  tlvLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  kind: 'chassis' | 'port',
): void {
  if (tlvLen < 2) {
    maskSpan(collector, intents, packetIndex, valueOff, tlvLen, `lldp-${kind}-short`)
    return
  }
  const subtype = buffer[valueOff]!
  const idOff = valueOff + 1
  const idLen = tlvLen - 1
  const macSubtype = kind === 'chassis' ? CHASSIS_MAC : PORT_MAC
  const ifNameSubtype = kind === 'chassis' ? CHASSIS_IFNAME : PORT_IFNAME
  const localSubtype = kind === 'chassis' ? CHASSIS_LOCAL : PORT_LOCAL

  if (subtype === macSubtype && idLen === 6) {
    mapMac(buffer, idOff, collector, mapping, intents, packetIndex)
    return
  }
  if (kind === 'chassis' && subtype === CHASSIS_NET && idLen >= 2) {
    const family = buffer[idOff]!
    if (family === 1 && idLen === 5) {
      mapIpv4(buffer, idOff + 1, collector, mapping, intents, packetIndex)
      return
    }
    if (family === 2 && idLen === 17) {
      mapIpv6(buffer, idOff + 1, collector, mapping, intents, packetIndex)
      return
    }
    maskSpan(collector, intents, packetIndex, idOff, idLen, 'lldp-chassis-net')
    return
  }
  if (subtype === ifNameSubtype || subtype === localSubtype) {
    // Schema-known short ifName (Gi0/1) preserve; otherwise hostname/opaque map
    const text = latin1(buffer, idOff, idLen)
    if (/^(Gi|Te|Fa|Eth|Ethernet|Port-Channel|Po|Vl|Vlan)\d/i.test(text) && text.length <= 16) {
      return
    }
    mapAsciiHostname(buffer, idOff, idLen, collector, mapping, intents, packetIndex)
    return
  }
  maskSpan(collector, intents, packetIndex, idOff, idLen, `lldp-${kind}-id`)
}

function sanitizeMgmtAddr(
  buffer: Uint8Array,
  valueOff: number,
  tlvLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (tlvLen < 2) {
    maskSpan(collector, intents, packetIndex, valueOff, tlvLen, 'lldp-mgmt-short')
    return
  }
  const addrStrLen = buffer[valueOff]!
  if (addrStrLen < 1 || 1 + addrStrLen > tlvLen) {
    maskSpan(collector, intents, packetIndex, valueOff, tlvLen, 'lldp-mgmt-len')
    return
  }
  const family = buffer[valueOff + 1]!
  const addrOff = valueOff + 2
  const addrLen = addrStrLen - 1
  if (family === 1 && addrLen === 4) {
    mapIpv4(buffer, addrOff, collector, mapping, intents, packetIndex)
  } else if (family === 2 && addrLen === 16) {
    mapIpv6(buffer, addrOff, collector, mapping, intents, packetIndex)
  } else if (addrLen > 0) {
    maskSpan(collector, intents, packetIndex, addrOff, addrLen, 'lldp-mgmt-addr')
  }
  // ifIndex (4) + OID length + OID preserved after address string
}

function sanitizeOrgTlv(
  buffer: Uint8Array,
  valueOff: number,
  tlvLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  policy: SanitizationPolicy,
  coverage: LayerCoverage[],
  tlvHdrOff: number,
): void {
  if (tlvLen < 4) {
    maskSpan(collector, intents, packetIndex, valueOff, tlvLen, 'lldp-org-short')
    coverage.push({ protocol: 'lldp', offset: tlvHdrOff, length: 2 + tlvLen, status: 'malformed' })
    return
  }
  const oui = (buffer[valueOff]! << 16) | (buffer[valueOff + 1]! << 8) | buffer[valueOff + 2]!
  const subtype = buffer[valueOff + 3]!
  const bodyOff = valueOff + 4
  const bodyLen = tlvLen - 4

  if (oui === OUI_MED) {
    if (subtype === MED_LOCATION) {
      // Civic / coordinate / ELIN — always mask both levels
      maskSpan(collector, intents, packetIndex, bodyOff, bodyLen, 'lldp-med-location')
      coverage.push({ protocol: 'lldp-med', offset: tlvHdrOff, length: 2 + tlvLen, status: 'redacted' })
      return
    }
    if (subtype === MED_NETWORK_POLICY) {
      // VLAN/DSCP for voice — remap VLAN id when present (bytes 1–2: AppType + flags/VLAN)
      if (bodyLen >= 4) {
        const vlan = ((buffer[bodyOff + 1]! & 0x01) << 8) | buffer[bodyOff + 2]!
        if (vlan > 0 && vlan < 4095) {
          const vlanOff = bodyOff + 1
          const canonical = `${vlan}`
          intents?.recordEntityReplacement(packetIndex, vlanOff, 'vlan', canonical, 2)
          try {
            collector.addDeferred(vlanOff, 2, ({ mapping: live }) => {
              const mapped = Number.parseInt(live.map('vlan', canonical), 10)
              if (!Number.isInteger(mapped) || mapped < 1 || mapped > 4094) return null
              const b0 = (buffer[vlanOff]! & 0xfe) | ((mapped >> 8) & 0x01)
              return new Uint8Array([b0, mapped & 0xff])
            }, { fallbackKind: 'digits', protocol: 'lldp-med', category: 'vlan', packetIndex })
          } catch { /* overlap */ }
        }
      }
      coverage.push({ protocol: 'lldp-med', offset: tlvHdrOff, length: 2 + tlvLen, status: 'covered' })
      return
    }
    if (subtype === MED_INV_SERIAL || subtype === MED_INV_ASSET) {
      mapOpaqueAscii(buffer, bodyOff, bodyLen, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'lldp-med', offset: tlvHdrOff, length: 2 + tlvLen, status: 'covered' })
      return
    }
    if (subtype === MED_INV_MFG || subtype === MED_INV_MODEL) {
      maskSpan(collector, intents, packetIndex, bodyOff, bodyLen, 'lldp-med-fingerprint')
      coverage.push({ protocol: 'lldp-med', offset: tlvHdrOff, length: 2 + tlvLen, status: 'redacted' })
      return
    }
    if (subtype === MED_INV_HW || subtype === MED_INV_FW || subtype === MED_INV_SW) {
      if (policy.preset === 'high-privacy') {
        maskSpan(collector, intents, packetIndex, bodyOff, bodyLen, 'lldp-med-rev')
        coverage.push({ protocol: 'lldp-med', offset: tlvHdrOff, length: 2 + tlvLen, status: 'redacted' })
      } else {
        coverage.push({ protocol: 'lldp-med', offset: tlvHdrOff, length: 2 + tlvLen, status: 'covered' })
      }
      return
    }
    maskSpan(collector, intents, packetIndex, bodyOff, bodyLen, 'lldp-med-unknown')
    coverage.push({ protocol: 'lldp-med', offset: tlvHdrOff, length: 2 + tlvLen, status: 'redacted' })
    return
  }

  if (oui === OUI_8021) {
    // Port VLAN ID / VLAN name — map VLAN id; name via detectors or mask
    if (subtype === 1 && bodyLen >= 2) {
      // Port VLAN ID
      const vlan = (buffer[bodyOff]! << 8) | buffer[bodyOff + 1]!
      if (vlan > 0 && vlan < 4095) {
        const canonical = `${vlan}`
        intents?.recordEntityReplacement(packetIndex, bodyOff, 'vlan', canonical, 2)
        try {
          collector.addDeferred(bodyOff, 2, ({ mapping: live }) => {
            const mapped = Number.parseInt(live.map('vlan', canonical), 10)
            if (!Number.isInteger(mapped) || mapped < 1 || mapped > 4094) return null
            return new Uint8Array([(mapped >> 8) & 0xff, mapped & 0xff])
          }, { fallbackKind: 'digits', protocol: 'lldp', category: 'vlan', packetIndex })
        } catch { /* overlap */ }
      }
      coverage.push({ protocol: 'lldp', offset: tlvHdrOff, length: 2 + tlvLen, status: 'covered' })
      return
    }
    if (subtype === 3 && bodyLen >= 3) {
      // VLAN name: VLAN id (2) + name
      const vlan = (buffer[bodyOff]! << 8) | buffer[bodyOff + 1]!
      if (vlan > 0 && vlan < 4095) {
        const canonical = `${vlan}`
        intents?.recordEntityReplacement(packetIndex, bodyOff, 'vlan', canonical, 2)
        try {
          collector.addDeferred(bodyOff, 2, ({ mapping: live }) => {
            const mapped = Number.parseInt(live.map('vlan', canonical), 10)
            if (!Number.isInteger(mapped) || mapped < 1 || mapped > 4094) return null
            return new Uint8Array([(mapped >> 8) & 0xff, mapped & 0xff])
          }, { fallbackKind: 'digits', protocol: 'lldp', category: 'vlan', packetIndex })
        } catch { /* overlap */ }
      }
      sanitizeDescription(buffer, bodyOff + 2, bodyLen - 2, collector, mapping, intents, packetIndex, policy)
      coverage.push({ protocol: 'lldp', offset: tlvHdrOff, length: 2 + tlvLen, status: 'covered' })
      return
    }
    coverage.push({ protocol: 'lldp', offset: tlvHdrOff, length: 2 + tlvLen, status: 'covered' })
    return
  }

  if (oui === OUI_8023) {
    // MAC/PHY, Power via MDI, Max frame — preserve
    coverage.push({ protocol: 'lldp', offset: tlvHdrOff, length: 2 + tlvLen, status: 'covered' })
    return
  }

  maskSpan(collector, intents, packetIndex, bodyOff, bodyLen, 'lldp-org-unknown')
  coverage.push({ protocol: 'lldp', offset: tlvHdrOff, length: 2 + tlvLen, status: 'redacted' })
}

function sanitizeDescription(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  policy: SanitizationPolicy,
): void {
  if (len <= 0) return
  // T63 — both levels mask until T69; keep signature for call-site compatibility.
  void buffer
  void mapping
  void policy
  maskSpan(collector, intents, packetIndex, abs, len, 'lldp-desc')
}

function mapAsciiHostname(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len <= 0) return
  const raw = latin1(buffer, abs, len)
  const canon = canonicalizeIdentity('hostname', raw.trim().toLowerCase())
  if (!canon) {
    maskSpan(collector, intents, packetIndex, abs, len, 'lldp-hostname')
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, 'hostname', canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const alias = live.aliasFor('hostname', canon, constraint, raw)
      return computeFixedLengthAsciiBytes(abs, len, alias)
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'lldp-hostname' })
    }
  }, { fallbackKind: 'text-x', protocol: 'lldp', category: 'hostname', packetIndex })
  void mapping
}

function mapOpaqueAscii(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len <= 0) return
  const raw = latin1(buffer, abs, len)
  const canon = canonicalizeIdentity('opaque-id', raw) ?? raw
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len, constraint, raw)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      return computeFixedLengthAsciiBytes(abs, len, live.aliasFor('opaque-id', canon, constraint, raw))
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'lldp-opaque' })
    }
  }, { fallbackKind: 'text-x', protocol: 'lldp-med', category: 'opaque-id', packetIndex })
  void mapping
}

function mapMac(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const parts: string[] = []
  for (let i = 0; i < 6; i++) parts.push(buffer[abs + i]!.toString(16).padStart(2, '0'))
  const text = parts.join(':')
  const canon = canonicalizeIdentity('mac', text)
  if (!canon) {
    maskSpan(collector, intents, packetIndex, abs, 6, 'lldp-mac')
    return
  }
  intents?.recordEntityReplacement(packetIndex, abs, 'mac', canon, 6, { kind: 'mac-wire' }, text)
  collector.addDeferred(abs, 6, ({ mapping: live }) => {
    const alias = live.map('mac', canon)
    const hex = alias.replace(/[^0-9a-f]/gi, '')
    if (hex.length < 12) {
      return createProtocolNeutralMaskFill({ length: 6, packetIndex, offset: abs, domain: 'lldp-mac' })
    }
    const out = new Uint8Array(6)
    for (let i = 0; i < 6; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    return out
  }, { fallbackKind: 'binary-mask', protocol: 'lldp', category: 'mac', packetIndex })
  void mapping
}

function mapIpv4(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const text = `${buffer[abs]!}.${buffer[abs + 1]!}.${buffer[abs + 2]!}.${buffer[abs + 3]!}`
  if (text === '0.0.0.0') return
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv4', text, 4)
  collector.addDeferred(abs, 4, ({ mapping: live }) => {
    const mapped = live.map('ipv4', text)
    return new Uint8Array(mapped.split('.').map(Number))
  }, { fallbackKind: 'binary-mask', protocol: 'lldp', category: 'ipv4', packetIndex })
  void mapping
}

function mapIpv6(
  buffer: Uint8Array,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const parts: string[] = []
  for (let i = 0; i < 16; i += 2) {
    parts.push(((buffer[abs + i]! << 8) | buffer[abs + i + 1]!).toString(16))
  }
  const text = parts.join(':')
  intents?.recordEntityReplacement(packetIndex, abs, 'ipv6', text, 16)
  collector.addDeferred(abs, 16, ({ mapping: live }) => {
    const mapped = live.map('ipv6', text)
    // Fail-closed mask if parse fails — keep length
    const fill = createProtocolNeutralMaskFill({ length: 16, packetIndex, offset: abs, domain: 'lldp-ipv6' })
    const hextets = mapped.split(':')
    if (hextets.length !== 8) return fill
    const out = new Uint8Array(16)
    for (let i = 0; i < 8; i++) {
      const v = Number.parseInt(hextets[i]!, 16)
      if (!Number.isInteger(v) || v < 0 || v > 0xffff) return fill
      out[i * 2] = (v >> 8) & 0xff
      out[i * 2 + 1] = v & 0xff
    }
    return out
  }, { fallbackKind: 'binary-mask', protocol: 'lldp', category: 'ipv6', packetIndex })
  void mapping
}

function maskSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  abs: number,
  len: number,
  reason: string,
): void {
  if (len <= 0) return
  maskPayloadSpan(collector, abs, len, intents, packetIndex, reason)
}

function latin1(buffer: Uint8Array, abs: number, len: number): string {
  return new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
}
