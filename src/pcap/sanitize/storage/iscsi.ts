/**
 * T42 — iSCSI (RFC 7143): TCP 3260; BHS preserve; Login IQN/CHAP; Data-In/Out mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { decodeAscii, mapAsciiIdentity, maskBytes } from './common.ts'

export const ISCSI_TCP_PORT = 3260

const OPC_SCSI_CMD = 0x01
const OPC_SCSI_DATA_OUT = 0x05
const OPC_LOGIN_REQ = 0x03
const OPC_TEXT_REQ = 0x04
const OPC_SCSI_DATA_IN = 0x25
const OPC_LOGIN_RSP = 0x23
const OPC_TEXT_RSP = 0x24

export function isIscsiPortHint(src: number, dst: number): boolean {
  return src === ISCSI_TCP_PORT || dst === ISCSI_TCP_PORT
}

export function looksLikeIscsi(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 48) return false
  const opcode = buffer[offset]! & 0x3f
  if (opcode > 0x3f) return false
  const totalAhs = buffer[offset + 4]!
  const dsl =
    ((buffer[offset + 5]! & 0xff) << 16)
    | ((buffer[offset + 6]! & 0xff) << 8)
    | (buffer[offset + 7]! & 0xff)
  const pad = (4 - (dsl % 4)) % 4
  const need = 48 + totalAhs * 4 + dsl + pad
  return need <= length + 48 // allow truncated capture of data segment
}

export function sanitizeIscsi(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  _highPrivacy: boolean,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isIscsiPortHint(srcPort, dstPort) && !looksLikeIscsi(buffer, offset, length)) {
    return null
  }
  if (length < 48) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos + 48 <= end) {
    const opcode = buffer[pos]! & 0x3f
    const totalAhs = buffer[pos + 4]!
    const dsl =
      ((buffer[pos + 5]! & 0xff) << 16)
      | ((buffer[pos + 6]! & 0xff) << 8)
      | (buffer[pos + 7]! & 0xff)
    const pad = (4 - (dsl % 4)) % 4
    const ahsBytes = totalAhs * 4
    const pduLen = 48 + ahsBytes + dsl + pad
    const take = Math.min(pduLen, end - pos)

    coverage.push({ protocol: 'iscsi', offset: pos, length: 48, status: 'covered' })
    if (ahsBytes > 0 && pos + 48 + ahsBytes <= end) {
      maskBytes(
        collector,
        intents,
        packetIndex,
        pos + 48,
        ahsBytes,
        'iscsi-ahs',
        'iscsi',
      )
      coverage.push({
        protocol: 'iscsi-body',
        offset: pos + 48,
        length: ahsBytes,
        status: 'redacted',
      })
    }

    const dataOff = pos + 48 + ahsBytes
    const dataAvail = Math.min(dsl, Math.max(0, end - dataOff))

    if (
      opcode === OPC_LOGIN_REQ
      || opcode === OPC_LOGIN_RSP
      || opcode === OPC_TEXT_REQ
      || opcode === OPC_TEXT_RSP
    ) {
      if (dataAvail > 0) {
        sanitizeLoginText(
          buffer,
          dataOff,
          dataAvail,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
          issues,
        )
      }
    } else if (
      opcode === OPC_SCSI_DATA_IN
      || opcode === OPC_SCSI_DATA_OUT
      || opcode === OPC_SCSI_CMD
    ) {
      // CDB lives in BHS for SCSI Cmd (bytes 32–47) — preserve opcodes/lengths already in header span.
      // Data segment (disk content / parameter data) always mask.
      if (dataAvail > 0) {
        maskBytes(collector, intents, packetIndex, dataOff, dataAvail, 'iscsi-data', 'iscsi')
        coverage.push({
          protocol: 'iscsi-data',
          offset: dataOff,
          length: dataAvail,
          status: 'redacted',
        })
        issues.push('iscsi-data-masked')
      }
    } else if (dataAvail > 0) {
      maskBytes(collector, intents, packetIndex, dataOff, dataAvail, 'iscsi-body', 'iscsi')
      coverage.push({
        protocol: 'iscsi-body',
        offset: dataOff,
        length: dataAvail,
        status: 'redacted',
      })
    }

    if (pad > 0 && dataOff + dsl + pad <= end) {
      coverage.push({
        protocol: 'iscsi',
        offset: dataOff + dsl,
        length: pad,
        status: 'covered',
      })
    }

    coverage.push({
      protocol: 'iscsi',
      offset: pos,
      length: take,
      status: 'covered',
    })
    pos += take
    if (take < pduLen) break
  }

  if (coverage.length === 0) return null
  return { coverage, issues }
}

function sanitizeLoginText(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  // NUL-separated key=value pairs
  let i = offset
  const end = offset + length
  while (i < end) {
    let j = i
    while (j < end && buffer[j] !== 0) j++
    const pairLen = j - i
    if (pairLen > 0) {
      const pair = decodeAscii(buffer, i, pairLen)
      const eq = pair.indexOf('=')
      if (eq > 0) {
        const key = pair.slice(0, eq)
        const valOff = i + eq + 1
        const valLen = pairLen - eq - 1
        if (key === 'CHAP_R' || key === 'CHAP_C' || key === 'CHAP_I') {
          maskBytes(collector, intents, packetIndex, valOff, valLen, 'iscsi-chap', 'iscsi')
          coverage.push({
            protocol: 'iscsi-chap',
            offset: valOff,
            length: valLen,
            status: 'redacted',
          })
          issues.push('iscsi-chap-masked')
        } else if (key === 'CHAP_N') {
          mapAsciiIdentity(
            buffer,
            valOff,
            valLen,
            'user-id',
            collector,
            mapping,
            intents,
            packetIndex,
            'iscsi',
          )
          coverage.push({
            protocol: 'iscsi-chap',
            offset: valOff,
            length: valLen,
            status: 'covered',
          })
        } else if (key === 'InitiatorName' || key === 'TargetName') {
          sanitizeIqn(buffer, valOff, valLen, collector, mapping, intents, packetIndex, coverage)
        } else if (key === 'TargetAddress') {
          sanitizeTargetAddress(
            buffer,
            valOff,
            valLen,
            collector,
            mapping,
            intents,
            packetIndex,
            coverage,
          )
        } else if (key === 'TargetAlias' || key === 'InitiatorAlias') {
          mapAsciiIdentity(
            buffer,
            valOff,
            valLen,
            'opaque-id',
            collector,
            mapping,
            intents,
            packetIndex,
            'iscsi',
          )
          coverage.push({
            protocol: 'iscsi-iqn',
            offset: valOff,
            length: valLen,
            status: 'covered',
          })
        } else {
          coverage.push({ protocol: 'iscsi', offset: i, length: pairLen, status: 'covered' })
        }
      } else {
        coverage.push({ protocol: 'iscsi', offset: i, length: pairLen, status: 'covered' })
      }
    }
    i = j + 1
  }
  coverage.push({ protocol: 'iscsi', offset, length, status: 'covered' })
}

/**
 * IQN: iqn.YYYY-MM.reversed-domain:name — preserve date prefix; map domain + name.
 */
function sanitizeIqn(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  const text = decodeAscii(buffer, offset, length)
  const m = /^iqn\.(\d{4}-\d{2})\.(.+)$/i.exec(text)
  if (!m) {
    mapAsciiIdentity(
      buffer,
      offset,
      length,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'iscsi',
    )
    coverage.push({ protocol: 'iscsi-iqn', offset, length, status: 'covered' })
    return
  }
  const datePart = `iqn.${m[1]}.`
  const rest = m[2]!
  const restOff = offset + datePart.length
  const colon = rest.indexOf(':')
  if (colon >= 0) {
    const domainLen = colon
    const nameOff = restOff + colon + 1
    const nameLen = rest.length - colon - 1
    if (domainLen > 0) {
      mapAsciiIdentity(
        buffer,
        restOff,
        domainLen,
        'hostname',
        collector,
        mapping,
        intents,
        packetIndex,
        'iscsi',
      )
    }
    if (nameLen > 0) {
      mapAsciiIdentity(
        buffer,
        nameOff,
        nameLen,
        'opaque-id',
        collector,
        mapping,
        intents,
        packetIndex,
        'iscsi',
      )
    }
  } else {
    mapAsciiIdentity(
      buffer,
      restOff,
      rest.length,
      'hostname',
      collector,
      mapping,
      intents,
      packetIndex,
      'iscsi',
    )
  }
  coverage.push({ protocol: 'iscsi-iqn', offset, length, status: 'covered' })
}

function sanitizeTargetAddress(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  // host[,port,tpgt] — map host via detectors/hostname; keep structure
  const text = decodeAscii(buffer, offset, length)
  const comma = text.indexOf(',')
  const hostLen = comma >= 0 ? comma : length
  if (hostLen > 0) {
    // IPv4 dotted → leave to opaque map as hostname (mapping handles IP categories via canonicalize)
    const host = text.slice(0, hostLen)
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
      // Map as opaque-id of same length (IP category needs binary path elsewhere)
      mapAsciiIdentity(
        buffer,
        offset,
        hostLen,
        'opaque-id',
        collector,
        mapping,
        intents,
        packetIndex,
        'iscsi',
      )
    } else {
      mapAsciiIdentity(
        buffer,
        offset,
        hostLen,
        'hostname',
        collector,
        mapping,
        intents,
        packetIndex,
        'iscsi',
      )
    }
  }
  coverage.push({ protocol: 'iscsi-iqn', offset, length, status: 'covered' })
}
