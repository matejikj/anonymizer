/**
 * T40 — Bluetooth HCI H4 (LINKTYPE_BLUETOOTH_HCI_H4 = 201) and BLE Linux monitor baseline.
 * BD_ADDR → mac (LE wire → canonical); device names → hostname; SMP keys always mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { computeFixedLengthAsciiBytes } from '../textPatch.ts'
import { createProtocolNeutralMaskFill } from '../maskFill.ts'
import { maskBytes, readU16le } from './common.ts'

export const LINKTYPE_BLUETOOTH_HCI_H4 = 201
export const LINKTYPE_BLUETOOTH_LE_LL = 251
export const LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256
/** Linux Bluetooth monitor (DLT_BLUETOOTH_LINUX_MONITOR). */
export const LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254

const HCI_COMMAND = 0x01
const HCI_ACL = 0x02
const HCI_EVENT = 0x04

const EVT_REMOTE_NAME = 0x07
const EVT_LE_META = 0x3e
const EVT_CMD_COMPLETE = 0x0e

const L2CAP_CID_SMP = 0x0006

export function sanitizeBluetoothHci(
  data: Uint8Array,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; issues: string[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (data.length < 1) {
    coverage.push({ protocol: 'bluetooth', offset: 0, length: 0, status: 'malformed' })
    return { coverage, issues, lastCoveredOffset: 0 }
  }

  const pktType = data[0]!
  coverage.push({ protocol: 'bluetooth', offset: 0, length: 1, status: 'covered' })

  if (pktType === HCI_EVENT && data.length >= 3) {
    const evt = data[1]!
    const plen = data[2]!
    coverage.push({ protocol: 'bluetooth-hci', offset: 1, length: 2 + Math.min(plen, data.length - 3), status: 'covered' })
    const body = 3
    if (evt === EVT_REMOTE_NAME && data.length >= body + 7) {
      // status(1) BD_ADDR(6 LE) name…
      mapBdAddrLe(data, body + 1, collector, mapping, intents, packetIndex)
      const nameOff = body + 7
      const nameLen = Math.min(248, data.length - nameOff)
      mapDeviceName(data, nameOff, nameLen, collector, mapping, intents, packetIndex)
    } else if (evt === EVT_LE_META && data.length > body) {
      sanitizeLeMeta(data, body, data.length - body, collector, mapping, packetIndex, intents, coverage, issues)
    } else if (evt === EVT_CMD_COMPLETE && data.length >= body + 3) {
      // status may carry BD_ADDR in some opcode responses — mask unknown payload
      if (data.length > body + 3) {
        // Keep opcode/status; mask remainder if looks like address-bearing
        const rem = data.length - (body + 3)
        if (rem >= 6) {
          // Heuristic: map first 6 as BD_ADDR when present
          mapBdAddrLe(data, body + 3, collector, mapping, intents, packetIndex)
          if (rem > 6) {
            maskBytes(
              collector,
              intents,
              packetIndex,
              body + 9,
              rem - 6,
              'bluetooth-evt',
              'bluetooth',
            )
          }
        }
      }
    } else if (plen > 0 && body + plen <= data.length) {
      // Other events — mask body (may contain keys / addresses)
      maskBytes(collector, intents, packetIndex, body, plen, 'bluetooth-evt', 'bluetooth')
      coverage.push({
        protocol: 'bluetooth-body',
        offset: body,
        length: plen,
        status: 'redacted',
      })
    }
  } else if (pktType === HCI_ACL && data.length >= 5) {
    // handle(2) length(2) L2CAP…
    const aclLen = readU16le(data, 3)
    coverage.push({ protocol: 'bluetooth-hci', offset: 1, length: 4, status: 'covered' })
    const l2 = 5
    if (data.length >= l2 + 4) {
      const cid = readU16le(data, l2 + 2)
      if (cid === L2CAP_CID_SMP) {
        maskBytes(
          collector,
          intents,
          packetIndex,
          l2,
          data.length - l2,
          'bluetooth-smp',
          'bluetooth',
        )
        coverage.push({
          protocol: 'bluetooth-smp',
          offset: l2,
          length: data.length - l2,
          status: 'redacted',
        })
        issues.push('bluetooth-smp-masked')
      } else {
        // ATT/GATT values — mask payload after L2CAP header
        if (data.length > l2 + 4) {
          maskBytes(
            collector,
            intents,
            packetIndex,
            l2 + 4,
            data.length - (l2 + 4),
            'bluetooth-acl',
            'bluetooth',
          )
          coverage.push({
            protocol: 'bluetooth-body',
            offset: l2 + 4,
            length: data.length - (l2 + 4),
            status: 'redacted',
          })
        }
        coverage.push({ protocol: 'bluetooth-l2cap', offset: l2, length: 4, status: 'covered' })
      }
    }
    void aclLen
  } else if (pktType === HCI_COMMAND && data.length >= 4) {
    coverage.push({ protocol: 'bluetooth-hci', offset: 1, length: 3, status: 'covered' })
    if (data.length > 4) {
      // Commands may carry BD_ADDR / PIN — mask params
      maskBytes(collector, intents, packetIndex, 4, data.length - 4, 'bluetooth-cmd', 'bluetooth')
      coverage.push({
        protocol: 'bluetooth-body',
        offset: 4,
        length: data.length - 4,
        status: 'redacted',
      })
    }
  } else {
    maskBytes(collector, intents, packetIndex, 1, data.length - 1, 'bluetooth-unknown', 'bluetooth')
    coverage.push({
      protocol: 'bluetooth-body',
      offset: 1,
      length: Math.max(0, data.length - 1),
      status: 'redacted',
    })
  }

  coverage.push({ protocol: 'bluetooth', offset: 0, length: data.length, status: 'covered' })
  return { coverage, issues, lastCoveredOffset: data.length }
}

/** BLE LL / monitor — map AdvA when present; mask PDU body (keys / names in AD). */
export function sanitizeBluetoothLeLl(
  data: Uint8Array,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): { coverage: LayerCoverage[]; issues: string[]; lastCoveredOffset: number } {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (data.length < 2) {
    coverage.push({ protocol: 'bluetooth', offset: 0, length: data.length, status: 'malformed' })
    return { coverage, issues, lastCoveredOffset: data.length }
  }
  // Access address (4) + header (2) + AdvA (6) on advertising PDUs — best-effort
  if (data.length >= 12) {
    coverage.push({ protocol: 'bluetooth', offset: 0, length: 6, status: 'covered' })
    mapBdAddrLe(data, 6, collector, mapping, intents, packetIndex)
    if (data.length > 12) {
      maskBytes(collector, intents, packetIndex, 12, data.length - 12, 'bluetooth-ll', 'bluetooth')
      coverage.push({
        protocol: 'bluetooth-body',
        offset: 12,
        length: data.length - 12,
        status: 'redacted',
      })
    }
  } else {
    maskBytes(collector, intents, packetIndex, 0, data.length, 'bluetooth-ll', 'bluetooth')
  }
  coverage.push({ protocol: 'bluetooth', offset: 0, length: data.length, status: 'covered' })
  issues.push('bluetooth-ll-baseline')
  return { coverage, issues, lastCoveredOffset: data.length }
}

function sanitizeLeMeta(
  data: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents: IntentCollector | undefined,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  if (length < 1) return
  const sub = data[offset]!
  // Advertising report (0x02) / extended (0x0d): contain address + data
  if ((sub === 0x02 || sub === 0x0d) && length >= 1 + 1 + 1 + 6) {
    // skip subevent + num reports; first report: event_type(1) addr_type(1) addr(6) …
    let pos = offset + 2
    if (sub === 0x02) {
      // legacy: event_type, addr_type, addr
      if (pos + 8 <= offset + length) {
        mapBdAddrLe(data, pos + 2, collector, mapping, intents, packetIndex)
        const dataLenOff = pos + 8
        if (dataLenOff < offset + length) {
          const dlen = data[dataLenOff]!
          const dOff = dataLenOff + 1
          if (dOff + dlen <= offset + length && dlen > 0) {
            maskBytes(collector, intents, packetIndex, dOff, dlen, 'bluetooth-adv', 'bluetooth')
            coverage.push({
              protocol: 'bluetooth-adv',
              offset: dOff,
              length: dlen,
              status: 'redacted',
            })
          }
        }
      }
    } else {
      maskBytes(collector, intents, packetIndex, offset + 1, length - 1, 'bluetooth-le-meta', 'bluetooth')
      coverage.push({
        protocol: 'bluetooth-body',
        offset: offset + 1,
        length: length - 1,
        status: 'redacted',
      })
    }
  } else {
    maskBytes(collector, intents, packetIndex, offset + 1, length - 1, 'bluetooth-le-meta', 'bluetooth')
    coverage.push({
      protocol: 'bluetooth-body',
      offset: offset + 1,
      length: Math.max(0, length - 1),
      status: 'redacted',
    })
  }
  void issues
}

/** BD_ADDR on wire is little-endian; SessionMapping mac uses colon-hex big-endian order. */
function mapBdAddrLe(
  data: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (offset + 6 > data.length) return
  const be = new Uint8Array(6)
  for (let i = 0; i < 6; i++) be[i] = data[offset + 5 - i]!
  // Preserve random address top bits from original wire byte0 (MSB of BE addr)
  const mac = Array.from(be)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':')
  intents?.recordEntityReplacement(packetIndex, offset, 'mac', mac, 6)
  collector.addDeferred(
    offset,
    6,
    ({ mapping: live }) => {
      const mapped = live.map('mac', mac)
      const parts = mapped.split(':').map((s) => Number.parseInt(s, 16))
      // Write little-endian; restore top 2 bits of random addr from original BE[0]
      const origTop = be[0]! & 0xc0
      parts[0] = (parts[0]! & 0x3f) | origTop
      const out = new Uint8Array(6)
      for (let i = 0; i < 6; i++) out[i] = parts[5 - i]!
      return out
    },
    { fallbackKind: 'binary-mask', protocol: 'bluetooth', category: 'mac', packetIndex },
  )
  void mapping
}

function mapDeviceName(
  data: Uint8Array,
  offset: number,
  maxLen: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  let len = 0
  while (len < maxLen && data[offset + len] !== 0) len++
  if (len === 0) return
  const raw = new TextDecoder('utf-8', { fatal: false }).decode(data.subarray(offset, offset + len))
  const canon = canonicalizeIdentity('hostname', raw) ?? raw
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, offset, 'hostname', canon, len, constraint, raw)
  collector.addDeferred(
    offset,
    len,
    ({ mapping: live }) => {
      try {
        return computeFixedLengthAsciiBytes(
          offset,
          len,
          live.aliasFor('hostname', canon, { kind: 'text-ascii', byteLength: len }, raw),
        )
      } catch {
        return createProtocolNeutralMaskFill({
          length: len,
          packetIndex,
          offset,
          domain: 'bluetooth-name',
        })
      }
    },
    { fallbackKind: 'text-x', protocol: 'bluetooth', category: 'hostname', packetIndex },
  )
  void mapping
}
