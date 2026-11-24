/**
 * T42 — DCE/RPC (MS-RPCE): TCP 135 + content probe; auth via T16; stub policy by UUID.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import {
  looksLikeNtlmssp,
  sanitizeNtlmssp,
  looksLikeSpnego,
  sanitizeSpnego,
} from '../../protocols/application/binproto/index.ts'
import { maskBytes, mapAsciiIdentity, readU16le, readU32le } from './common.ts'

export const DCERPC_EPM_TCP_PORT = 135

/** Well-known interface UUIDs (lowercase hex, no braces). */
export const IFACE = {
  epm: 'e1af83085d1f11c991a408002b14a0fa',
  samr: '123457781234abcdef000123456789ac',
  lsarpc: '123457781234abcdef000123456789ab',
  netlogon: '123456781234abcdef0001234567cffb',
  drsuapi: 'e35142354b0611d1ab0400c04fc2dcd2',
  srvsvc: '4b324fc871cf11d0a5ba00c04fd91e09',
  wkssvc: '6bffd098a11236108571722a00000000',
  spoolss: '123456781234abcdff000123456789ab',
} as const

const PTYPE_REQUEST = 0
const PTYPE_RESPONSE = 2
const PTYPE_FAULT = 3
const PTYPE_BIND = 11
const PTYPE_BIND_ACK = 12
const PTYPE_ALTER = 14
const PTYPE_ALTER_ACK = 15
const PTYPE_AUTH3 = 16

const AUTH_LEVEL_PKT_PRIVACY = 6

export function isDcerpcPortHint(src: number, dst: number): boolean {
  return src === DCERPC_EPM_TCP_PORT || dst === DCERPC_EPM_TCP_PORT
}

export function looksLikeDcerpc(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 16) return false
  const vers = buffer[offset]!
  const minor = buffer[offset + 1]!
  if (vers !== 5 || minor !== 0) return false
  const ptype = buffer[offset + 2]!
  if (ptype > 19) return false
  const frag = readU16le(buffer, offset + 8)
  if (frag < 16 || frag > length) return false
  return true
}

export function sanitizeDcerpc(
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
  if (!isDcerpcPortHint(srcPort, dstPort) && !looksLikeDcerpc(buffer, offset, length)) {
    return null
  }
  if (!looksLikeDcerpc(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset
  let lastIface: string | null = null

  while (pos + 16 <= end) {
    if (!looksLikeDcerpc(buffer, pos, end - pos)) break
    const ptype = buffer[pos + 2]!
    const fragLen = readU16le(buffer, pos + 8)
    const authLen = readU16le(buffer, pos + 10)
    if (fragLen < 16 || pos + fragLen > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'dcerpc-desync', 'dcerpc')
      coverage.push({
        protocol: 'dcerpc-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('dcerpc-frame-desync')
      break
    }

    // Common header preserve
    coverage.push({ protocol: 'dcerpc', offset: pos, length: 16, status: 'covered' })

    const authLevel = authLen > 0 && fragLen >= 16 + authLen + 8
      ? buffer[pos + fragLen - authLen - 8 + 1]!
      : 0
    const stubStart = pos + 16
    let stubEnd = pos + fragLen
    if (authLen > 0) {
      const authTrailerStart = pos + fragLen - authLen - 8
      if (authTrailerStart >= stubStart) {
        stubEnd = authTrailerStart
        // auth_type..auth_context_id (8) + auth_value
        coverage.push({
          protocol: 'dcerpc',
          offset: authTrailerStart,
          length: 8,
          status: 'covered',
        })
        const authValOff = authTrailerStart + 8
        sanitizeAuthVerifier(
          buffer,
          authValOff,
          authLen,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
          issues,
        )
      }
    }

    if (ptype === PTYPE_BIND || ptype === PTYPE_ALTER) {
      lastIface = sanitizeBindBody(
        buffer,
        stubStart,
        stubEnd - stubStart,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
      )
    } else if (ptype === PTYPE_BIND_ACK || ptype === PTYPE_ALTER_ACK) {
      sanitizeBindAck(
        buffer,
        stubStart,
        stubEnd - stubStart,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
      )
    } else if (
      ptype === PTYPE_REQUEST
      || ptype === PTYPE_RESPONSE
      || ptype === PTYPE_FAULT
      || ptype === PTYPE_AUTH3
    ) {
      if (authLevel >= AUTH_LEVEL_PKT_PRIVACY && stubEnd > stubStart) {
        coverage.push({
          protocol: 'dcerpc',
          offset: stubStart,
          length: stubEnd - stubStart,
          status: 'encrypted',
        })
      } else {
        sanitizeStub(
          buffer,
          stubStart,
          stubEnd - stubStart,
          lastIface,
          ptype,
          collector,
          mapping,
          intents,
          packetIndex,
          coverage,
          issues,
        )
      }
    } else if (stubEnd > stubStart) {
      maskBytes(collector, intents, packetIndex, stubStart, stubEnd - stubStart, 'dcerpc-body', 'dcerpc')
      coverage.push({
        protocol: 'dcerpc-body',
        offset: stubStart,
        length: stubEnd - stubStart,
        status: 'redacted',
      })
    }

    // Parent span for CF-09 continuity
    coverage.push({ protocol: 'dcerpc', offset: pos, length: fragLen, status: 'covered' })
    pos += fragLen
  }

  if (coverage.length === 0) return null
  // Claim dynamic endpoint as DCE/RPC (not unsupported)
  if (srcPort !== DCERPC_EPM_TCP_PORT && srcPort > 0) {
    intents?.recordPortFlowHint(`tcp/${srcPort}`, 'other')
  }
  if (dstPort !== DCERPC_EPM_TCP_PORT && dstPort > 0) {
    intents?.recordPortFlowHint(`tcp/${dstPort}`, 'other')
  }
  return { coverage, issues }
}

function sanitizeAuthVerifier(
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
  if (length <= 0) return
  if (looksLikeNtlmssp(buffer, offset, length)) {
    sanitizeNtlmssp(buffer, offset, length, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'dcerpc-auth', offset, length, status: 'covered' })
    return
  }
  if (looksLikeSpnego(buffer, offset, length)) {
    sanitizeSpnego(buffer, offset, length, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'dcerpc-auth', offset, length, status: 'covered' })
    return
  }
  maskBytes(collector, intents, packetIndex, offset, length, 'dcerpc-auth', 'dcerpc')
  coverage.push({ protocol: 'dcerpc-auth', offset, length, status: 'redacted' })
  issues.push('dcerpc-auth-masked')
}

function uuidAt(buffer: Uint8Array, offset: number): string | null {
  if (offset + 16 > buffer.length) return null
  const parts: string[] = []
  for (let i = 0; i < 16; i++) {
    parts.push(buffer[offset + i]!.toString(16).padStart(2, '0'))
  }
  // MS UUID wire: time_low LE, time_mid LE, time_hi LE, then clock+node BE-ish bytes as-is
  const b = buffer.subarray(offset, offset + 16)
  const tlow = readU32le(b, 0).toString(16).padStart(8, '0')
  const tmid = readU16le(b, 4).toString(16).padStart(4, '0')
  const thi = readU16le(b, 6).toString(16).padStart(4, '0')
  const rest = Array.from(b.subarray(8, 16), (x) => x.toString(16).padStart(2, '0')).join('')
  void parts
  return `${tlow}${tmid}${thi}${rest}`
}

function sanitizeBindBody(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): string | null {
  // BIND: max_xmit, max_recv, assoc_group, n_ctx, then context elements with abstract syntax UUID
  if (length < 8) {
    maskBytes(collector, intents, packetIndex, offset, length, 'dcerpc-bind', 'dcerpc')
    return null
  }
  coverage.push({ protocol: 'dcerpc', offset, length: Math.min(8, length), status: 'covered' })
  let iface: string | null = null
  // Scan for known interface UUIDs in the bind body (NDR layout varies; UUID is 16B aligned)
  for (let o = offset; o + 16 <= offset + length; o += 4) {
    const id = uuidAt(buffer, o)
    if (!id) continue
    if (
      id === IFACE.epm
      || id === IFACE.samr
      || id === IFACE.lsarpc
      || id === IFACE.netlogon
      || id === IFACE.drsuapi
      || id === IFACE.srvsvc
      || id === IFACE.wkssvc
      || id === IFACE.spoolss
    ) {
      iface = id
      coverage.push({ protocol: 'dcerpc-iface', offset: o, length: 16, status: 'covered' })
      break
    }
  }
  // Remainder of bind body after header: preserve lengths we don't rewrite
  if (length > 8) {
    coverage.push({ protocol: 'dcerpc', offset: offset + 8, length: length - 8, status: 'covered' })
  }
  void collector
  void mapping
  void intents
  void packetIndex
  return iface
}

function sanitizeBindAck(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  // BIND_ACK may carry secondary address (port string) — map digits as opaque, register port
  if (length < 8) {
    maskBytes(collector, intents, packetIndex, offset, length, 'dcerpc-bind-ack', 'dcerpc')
    return
  }
  coverage.push({ protocol: 'dcerpc', offset, length: 8, status: 'covered' })
  // secondary address: length-prefixed ASCII port (often)
  if (length >= 10) {
    const secLen = readU16le(buffer, offset + 8)
    if (secLen > 0 && 10 + secLen <= offset + length) {
      const addrOff = offset + 10
      const text = new TextDecoder('ascii', { fatal: false }).decode(
        buffer.subarray(addrOff, addrOff + secLen),
      )
      const portMatch = /^(\d{1,5})/.exec(text.replace(/\0+$/, ''))
      if (portMatch) {
        const port = Number(portMatch[1])
        if (port > 0 && port < 65536) {
          intents?.recordPortFlowHint(`tcp/${port}`, 'other')
        }
      }
      // Keep port number digits (semantic service registration); map non-digit host if present
      if (/[A-Za-z]/.test(text)) {
        mapAsciiIdentity(
          buffer,
          addrOff,
          secLen,
          'hostname',
          collector,
          mapping,
          intents,
          packetIndex,
          'dcerpc',
        )
      }
      coverage.push({ protocol: 'dcerpc-epm', offset: addrOff, length: secLen, status: 'covered' })
    }
  }
  coverage.push({ protocol: 'dcerpc', offset, length, status: 'covered' })
}

function sanitizeStub(
  buffer: Uint8Array,
  offset: number,
  length: number,
  iface: string | null,
  ptype: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  if (length <= 0) return
  // REQUEST has alloc_hint(4)+context_id(2)+opnum(2) before NDR
  let body = offset
  let bodyLen = length
  if (ptype === PTYPE_REQUEST && length >= 8) {
    coverage.push({ protocol: 'dcerpc', offset, length: 8, status: 'covered' })
    body = offset + 8
    bodyLen = length - 8
  } else if (ptype === PTYPE_RESPONSE && length >= 8) {
    coverage.push({ protocol: 'dcerpc', offset, length: 8, status: 'covered' })
    body = offset + 8
    bodyLen = length - 8
  }

  if (iface === IFACE.netlogon || iface === IFACE.drsuapi) {
    maskBytes(collector, intents, packetIndex, body, bodyLen, 'dcerpc-secret', 'dcerpc')
    coverage.push({
      protocol: iface === IFACE.netlogon ? 'dcerpc-netlogon' : 'dcerpc-drsuapi',
      offset: body,
      length: bodyLen,
      status: 'redacted',
    })
    issues.push(iface === IFACE.netlogon ? 'dcerpc-netlogon-masked' : 'dcerpc-drsuapi-masked')
    return
  }

  if (iface === IFACE.epm) {
    // EPM towers may embed IP/port — mask opaque tower bytes; register any ASCII port digits
    scanAndHintPorts(buffer, body, bodyLen, intents)
    maskBytes(collector, intents, packetIndex, body, bodyLen, 'dcerpc-epm-tower', 'dcerpc')
    coverage.push({ protocol: 'dcerpc-epm', offset: body, length: bodyLen, status: 'redacted' })
    return
  }

  // SAMR/LSA/SRVSVC/unknown: fail-closed stub mask (NDR without IDL)
  maskBytes(collector, intents, packetIndex, body, bodyLen, 'dcerpc-stub', 'dcerpc')
  coverage.push({ protocol: 'dcerpc-body', offset: body, length: bodyLen, status: 'redacted' })
  void mapping
}

function scanAndHintPorts(
  buffer: Uint8Array,
  offset: number,
  length: number,
  intents: IntentCollector | undefined,
): void {
  // Look for ASCII decimal ports in tower bytes (secondary address style)
  const text = new TextDecoder('latin1').decode(buffer.subarray(offset, offset + length))
  for (const m of text.matchAll(/(?:^|[^0-9])(\d{4,5})(?:[^0-9]|$)/g)) {
    const port = Number(m[1])
    if (port >= 1024 && port < 65536) {
      intents?.recordPortFlowHint(`tcp/${port}`, 'other')
    }
  }
}
