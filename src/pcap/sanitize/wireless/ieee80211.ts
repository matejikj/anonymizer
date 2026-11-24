/**
 * T40 — IEEE 802.11 MAC frames (LINKTYPE_IEEE802_11 = 105; body after radiotap).
 * Map addr1–4; SSID IE → `ssid` category (`ssid/<hex>`); WPS serial/UUID mask; protected body mask;
 * unprotected LLC/SNAP → EAPOL or ethertype continue hint.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { sanitizeEapol } from '../eapol.ts'
import { mapMacAt, mapSsidBytes, maskBytes, readU16le } from './common.ts'

export const LINKTYPE_IEEE802_11 = 105

const FC_PROTECTED = 0x4000
const FC_TODS = 0x0100
const FC_FROMDS = 0x0200
const FC_ORDER = 0x8000

const TYPE_MGMT = 0
const TYPE_CTRL = 1
const TYPE_DATA = 2

const SUBTYPE_BEACON = 8
const SUBTYPE_PROBE_REQ = 4
const SUBTYPE_PROBE_RESP = 5
const SUBTYPE_AUTH = 11

const IE_SSID = 0
const IE_VENDOR = 221
const WFA_OUI0 = 0x00
const WFA_OUI1 = 0x50
const WFA_OUI2 = 0xf2
const WFA_WPS = 0x04

export interface Ieee80211Result {
  readonly coverage: LayerCoverage[]
  readonly issues: string[]
  /** Absolute offset of LLC/payload after 802.11 header (for continue). */
  readonly payloadOffset: number
  readonly payloadLength: number
  readonly protectedFrame: boolean
  /** When true, caller should not continue (body already handled). */
  readonly done: boolean
  readonly lastCoveredOffset: number
  /** Synthetic ethertype when LLC/SNAP decoded (e.g. 0x888e EAPOL, 0x0800 IPv4). */
  readonly etherType?: number
}

export function sanitizeIeee80211(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  highPrivacy: boolean,
): Ieee80211Result {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const end = data.length
  if (end - offset < 10) {
    coverage.push({ protocol: 'ieee80211', offset, length: end - offset, status: 'malformed' })
    return {
      coverage,
      issues: ['ieee80211-trunc'],
      payloadOffset: offset,
      payloadLength: 0,
      protectedFrame: false,
      done: true,
      lastCoveredOffset: end,
    }
  }

  const fc = readU16le(data, offset)
  const type = (fc >> 2) & 0x3
  const subtype = (fc >> 4) & 0xf
  const toDs = (fc & FC_TODS) !== 0
  const fromDs = (fc & FC_FROMDS) !== 0
  const protectedFrame = (fc & FC_PROTECTED) !== 0
  const order = (fc & FC_ORDER) !== 0

  let hdrLen = 24
  if (type === TYPE_CTRL) {
    // CTS/ACK: 10 bytes; RTS: 16; others vary — baseline map addr1 only
    hdrLen = subtype === 0xc /* CTS */ || subtype === 0xd /* ACK */ ? 10 : 16
  } else if (type === TYPE_DATA) {
    if (toDs && fromDs) hdrLen = 30
    if (subtype & 0x8) hdrLen += 2 // QoS
    if (order && (subtype & 0x8)) hdrLen += 4 // HT ctrl
  } else if (type === TYPE_MGMT) {
    if (order) hdrLen += 4
  }

  if (offset + hdrLen > end) {
    coverage.push({ protocol: 'ieee80211', offset, length: end - offset, status: 'malformed' })
    maskBytes(collector, intents, packetIndex, offset, end - offset, 'ieee80211-trunc', 'ieee80211')
    return {
      coverage,
      issues: ['ieee80211-hdr-trunc'],
      payloadOffset: offset,
      payloadLength: 0,
      protectedFrame,
      done: true,
      lastCoveredOffset: end,
    }
  }

  // Addresses
  mapMacAt(data, offset + 4, collector, mapping, intents, packetIndex, 'ieee80211') // addr1
  if (hdrLen >= 16) {
    mapMacAt(data, offset + 10, collector, mapping, intents, packetIndex, 'ieee80211') // addr2
  }
  if (hdrLen >= 24) {
    mapMacAt(data, offset + 16, collector, mapping, intents, packetIndex, 'ieee80211') // addr3
  }
  if (hdrLen >= 30 && toDs && fromDs) {
    mapMacAt(data, offset + 24, collector, mapping, intents, packetIndex, 'ieee80211') // addr4
  }

  coverage.push({ protocol: 'ieee80211', offset, length: hdrLen, status: 'covered' })

  const bodyOff = offset + hdrLen
  const bodyLen = end - bodyOff

  if (bodyLen <= 0) {
    coverage.push({ protocol: 'ieee80211', offset, length: end - offset, status: 'covered' })
    return {
      coverage,
      issues,
      payloadOffset: bodyOff,
      payloadLength: 0,
      protectedFrame,
      done: true,
      lastCoveredOffset: end,
    }
  }

  if (protectedFrame) {
    // Weak/unknown cipher without RSN session proof → mask (not encrypted-preserved).
    maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'ieee80211-protected', 'ieee80211')
    coverage.push({
      protocol: 'ieee80211-protected',
      offset: bodyOff,
      length: bodyLen,
      status: 'redacted',
    })
    coverage.push({ protocol: 'ieee80211', offset, length: end - offset, status: 'covered' })
    issues.push('ieee80211-protected-masked')
    return {
      coverage,
      issues,
      payloadOffset: bodyOff,
      payloadLength: bodyLen,
      protectedFrame: true,
      done: true,
      lastCoveredOffset: end,
    }
  }

  if (type === TYPE_MGMT) {
    sanitizeMgmtBody(
      data,
      bodyOff,
      bodyLen,
      subtype,
      collector,
      mapping,
      packetIndex,
      intents,
      highPrivacy,
      coverage,
      issues,
    )
    coverage.push({ protocol: 'ieee80211', offset, length: end - offset, status: 'covered' })
    return {
      coverage,
      issues,
      payloadOffset: bodyOff,
      payloadLength: bodyLen,
      protectedFrame: false,
      done: true,
      lastCoveredOffset: end,
    }
  }

  if (type === TYPE_CTRL) {
    // No sensitive body in baseline
    coverage.push({ protocol: 'ieee80211', offset, length: end - offset, status: 'covered' })
    return {
      coverage,
      issues,
      payloadOffset: bodyOff,
      payloadLength: bodyLen,
      protectedFrame: false,
      done: true,
      lastCoveredOffset: end,
    }
  }

  // Data — LLC/SNAP
  if (bodyLen >= 8 && data[bodyOff] === 0xaa && data[bodyOff + 1] === 0xaa && data[bodyOff + 2] === 0x03) {
    const etherType = (data[bodyOff + 6]! << 8) | data[bodyOff + 7]!
    coverage.push({ protocol: 'ieee80211-llc', offset: bodyOff, length: 8, status: 'covered' })
    const snapPayload = bodyOff + 8
    const snapLen = end - snapPayload
    if (etherType === 0x888e && snapLen > 0) {
      const eapol = sanitizeEapol(
        data,
        snapPayload,
        snapLen,
        collector,
        mapping,
        intents,
        packetIndex,
      )
      coverage.push(...eapol.coverage)
      if (eapol.issues) for (const i of eapol.issues) issues.push(i)
      coverage.push({ protocol: 'ieee80211', offset, length: end - offset, status: 'covered' })
      return {
        coverage,
        issues,
        payloadOffset: snapPayload,
        payloadLength: snapLen,
        protectedFrame: false,
        done: true,
        lastCoveredOffset: end,
        etherType,
      }
    }
    // IPv4/IPv6 — let caller continue if desired; mark LLC covered and return continue hint
    if (etherType === 0x0800 || etherType === 0x86dd) {
      coverage.push({ protocol: 'ieee80211', offset, length: bodyOff + 8 - offset, status: 'covered' })
      return {
        coverage,
        issues,
        payloadOffset: snapPayload,
        payloadLength: snapLen,
        protectedFrame: false,
        done: false,
        lastCoveredOffset: snapPayload,
        etherType,
      }
    }
    if (snapLen > 0) {
      maskBytes(collector, intents, packetIndex, snapPayload, snapLen, 'ieee80211-data', 'ieee80211')
      coverage.push({
        protocol: 'ieee80211-body',
        offset: snapPayload,
        length: snapLen,
        status: 'redacted',
      })
    }
    coverage.push({ protocol: 'ieee80211', offset, length: end - offset, status: 'covered' })
    return {
      coverage,
      issues,
      payloadOffset: snapPayload,
      payloadLength: snapLen,
      protectedFrame: false,
      done: true,
      lastCoveredOffset: end,
      etherType,
    }
  }

  maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'ieee80211-data', 'ieee80211')
  coverage.push({
    protocol: 'ieee80211-body',
    offset: bodyOff,
    length: bodyLen,
    status: 'redacted',
  })
  coverage.push({ protocol: 'ieee80211', offset, length: end - offset, status: 'covered' })
  return {
    coverage,
    issues,
    payloadOffset: bodyOff,
    payloadLength: bodyLen,
    protectedFrame: false,
    done: true,
    lastCoveredOffset: end,
  }
}

function sanitizeMgmtBody(
  data: Uint8Array,
  offset: number,
  length: number,
  subtype: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  highPrivacy: boolean,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  // Beacon/Probe Resp: fixed 12 bytes; Probe Req: no fixed; Auth: 6 bytes
  let pos = offset
  const end = offset + length
  if (subtype === SUBTYPE_BEACON || subtype === SUBTYPE_PROBE_RESP) {
    if (length < 12) {
      maskBytes(collector, intents, packetIndex, offset, length, 'ieee80211-mgmt', 'ieee80211')
      return
    }
    pos = offset + 12
    coverage.push({ protocol: 'ieee80211-mgmt', offset, length: 12, status: 'covered' })
  } else if (subtype === SUBTYPE_AUTH) {
    // Auth algorithm/seq/status — SAE commit/confirm body masked
    if (length >= 6) {
      coverage.push({ protocol: 'ieee80211-mgmt', offset, length: 6, status: 'covered' })
      if (length > 6) {
        maskBytes(collector, intents, packetIndex, offset + 6, length - 6, 'ieee80211-sae', 'ieee80211')
        coverage.push({
          protocol: 'ieee80211-sae',
          offset: offset + 6,
          length: length - 6,
          status: 'redacted',
        })
        issues.push('ieee80211-sae-masked')
      }
      return
    }
  } else if (subtype === SUBTYPE_PROBE_REQ) {
    coverage.push({ protocol: 'ieee80211-mgmt', offset, length: 0, status: 'covered' })
  } else {
    // Other mgmt — mask body (may contain IE identities)
    maskBytes(collector, intents, packetIndex, offset, length, 'ieee80211-mgmt', 'ieee80211')
    coverage.push({
      protocol: 'ieee80211-body',
      offset,
      length,
      status: 'redacted',
    })
    return
  }

  // IE walk
  while (pos + 2 <= end) {
    const id = data[pos]!
    const len = data[pos + 1]!
    if (pos + 2 + len > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'ieee80211-ie-trunc', 'ieee80211')
      break
    }
    const valOff = pos + 2
    if (id === IE_SSID) {
      if (highPrivacy && subtype === SUBTYPE_PROBE_REQ && len > 0) {
        // Probe Request SSID list = location history
        maskBytes(collector, intents, packetIndex, valOff, len, 'ssid-probe-hp', 'ieee80211')
        coverage.push({
          protocol: 'ieee80211-ssid',
          offset: valOff,
          length: len,
          status: 'redacted',
        })
      } else {
        mapSsidBytes(data, valOff, len, collector, mapping, intents, packetIndex, 'ieee80211')
        coverage.push({
          protocol: 'ieee80211-ssid',
          offset: valOff,
          length: Math.max(len, 0),
          status: 'covered',
        })
      }
    } else if (id === IE_VENDOR && len >= 4) {
      const isWps =
        data[valOff] === WFA_OUI0
        && data[valOff + 1] === WFA_OUI1
        && data[valOff + 2] === WFA_OUI2
        && data[valOff + 3] === WFA_WPS
      if (isWps) {
        // Preserve OUI+type; mask WPS TLVs (serial, UUID, PIN, device name)
        if (len > 4) {
          maskBytes(
            collector,
            intents,
            packetIndex,
            valOff + 4,
            len - 4,
            'ieee80211-wps',
            'ieee80211',
          )
        }
        coverage.push({
          protocol: 'ieee80211-wps',
          offset: pos,
          length: 2 + len,
          status: 'redacted',
        })
        issues.push('ieee80211-wps-masked')
      } else {
        // Unknown vendor IE — mask value (often hostname / AP name)
        maskBytes(collector, intents, packetIndex, valOff, len, 'ieee80211-vendor-ie', 'ieee80211')
        coverage.push({
          protocol: 'ieee80211-vendor-ie',
          offset: pos,
          length: 2 + len,
          status: 'redacted',
        })
      }
    } else {
      // rates / RSN / country / HT… preserve structurally
      coverage.push({
        protocol: 'ieee80211-ie',
        offset: pos,
        length: 2 + len,
        status: 'covered',
      })
    }
    pos += 2 + len
  }
}
