/**
 * T60 — PFCP v1 (TS 29.244) Sx/N4 sanitizer.
 * Header SEID ≠ GTP TEID; F-SEID / Node ID / F-TEID / UE IP / User ID structured;
 * SDF/PFD/unknown enterprise IE values masked; rule IDs and causes preserved.
 */

import type { MappingLike } from '../anonymization/mapping.ts'
import type { IntentCollector } from '../discovery/intentCollector.ts'
import { canonicalizeIdentity } from '../../mapping/canonicalize.ts'
import {
  decodeTbcd,
  encodeTbcd,
  remapTbcdBytes,
  TBCD_GSM,
  normalizeImsiDigits,
  normalizeImeiDigits,
} from '../protocols/application/binproto/tbcd.ts'
import type { PatchCollector } from './PatchCollector.ts'
import { deferredBinaryMapMeta } from './deferredMapMeta.ts'
import type { AppLayerResult, LayerCoverage } from './types.ts'
import { createProtocolNeutralMaskFill } from './maskFill.ts'
import { computeFixedLengthAsciiBytes } from './textPatch.ts'
import { patchTeid } from './gtp.ts'
import type { PayloadTimeSession } from '../kernel/payloadTimeCodec.ts'
import type { ApplicationFlowEndpoint } from './applicationDispatchTypes.ts'
import {
  pfcpSessionGraphForTransport,
  pfcpTransportSessionKey,
  seidMappingCanonical,
  type PfcpSeidScope,
} from './pfcp/pfcpSessionGraph.ts'

export { seidCanonicalKey, seidMappingCanonical, pfcpTransportSessionKey } from './pfcp/pfcpSessionGraph.ts'

export const PFCP_UDP_PORT = 8805

interface PfcpMessageContext {
  readonly receiveEndpoint: string
  readonly generation: number
  readonly msgType: number
  readonly headerSeidHex: string | null
  readonly graph: ReturnType<typeof pfcpSessionGraphForTransport>
}

const MAX_IE_DEPTH = 8
const MAX_MESSAGES = 8
const NTP_UNIX_DELTA = 2208988800n

/** TS 29.244 Table 8.1.2-1 (baseline Release 18). */
const IE = {
  CREATE_PDR: 1,
  PDI: 2,
  CREATE_FAR: 3,
  FORWARDING_PARAMETERS: 4,
  DUPLICATING_PARAMETERS: 5,
  CREATE_URR: 6,
  CREATE_QER: 7,
  CREATED_PDR: 8,
  UPDATE_PDR: 9,
  UPDATE_FAR: 10,
  UPDATE_FORWARDING_PARAMETERS: 11,
  UPDATE_URR: 13,
  UPDATE_QER: 14,
  REMOVE_PDR: 15,
  REMOVE_FAR: 16,
  REMOVE_URR: 17,
  REMOVE_QER: 18,
  CAUSE: 19,
  SOURCE_INTERFACE: 20,
  F_TEID: 21,
  NETWORK_INSTANCE: 22,
  SDF_FILTER: 23,
  APPLICATION_ID: 24,
  GATE_STATUS: 25,
  MBR: 26,
  GBR: 27,
  QER_CORRELATION_ID: 28,
  PRECEDENCE: 29,
  PDR_ID: 56,
  F_SEID: 57,
  NODE_ID: 60,
  PFD_CONTENTS: 61,
  UE_IP_ADDRESS: 93,
  OUTER_HEADER_CREATION: 84,
  OUTER_HEADER_REMOVAL: 95,
  RECOVERY_TIME_STAMP: 96,
  CREATE_BAR: 85,
  UPDATE_BAR: 86,
  REMOVE_BAR: 87,
  BAR_ID: 88,
  USER_ID: 141,
  APN_DNN: 159,
  ALTERNATIVE_SMF_IP: 178,
  CP_PFCP_ENTITY_IP: 185,
  TRACE_INFORMATION: 152,
} as const

const GROUPED = new Set<number>([
  IE.CREATE_PDR,
  IE.PDI,
  IE.CREATE_FAR,
  IE.FORWARDING_PARAMETERS,
  IE.DUPLICATING_PARAMETERS,
  IE.CREATE_URR,
  IE.CREATE_QER,
  IE.CREATED_PDR,
  IE.UPDATE_PDR,
  IE.UPDATE_FAR,
  IE.UPDATE_FORWARDING_PARAMETERS,
  IE.UPDATE_URR,
  IE.UPDATE_QER,
  IE.REMOVE_PDR,
  IE.REMOVE_FAR,
  IE.REMOVE_URR,
  IE.REMOVE_QER,
  IE.CREATE_BAR,
  IE.UPDATE_BAR,
  IE.REMOVE_BAR,
])

/** Structural / non-identity IEs — framing preserved. */
const PRESERVE = new Set<number>([
  IE.CAUSE,
  IE.SOURCE_INTERFACE,
  IE.GATE_STATUS,
  IE.MBR,
  IE.GBR,
  IE.QER_CORRELATION_ID,
  IE.PRECEDENCE,
  IE.PDR_ID,
  IE.BAR_ID,
  IE.OUTER_HEADER_REMOVAL,
])

export function isPfcpPortHint(src: number, dst: number): boolean {
  return src === PFCP_UDP_PORT || dst === PFCP_UDP_PORT
}

/**
 * PFCP v1 grammar probe: version=1, valid message length vs buffer,
 * known message-type band (node 1–15 / session 50–57), SEID flag consistent.
 * Port alone is never sufficient (UDP 2152 is GTP-U).
 */
export function looksLikePfcp(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const flags = data[offset]!
  const ver = (flags >> 5) & 0x7
  if (ver !== 1) return false
  const sFlag = (flags >> 0) & 0x1
  const msgType = data[offset + 1]!
  const msgLen = (data[offset + 2]! << 8) | data[offset + 3]!
  // Length excludes first 4 octets
  if (4 + msgLen > length) return false
  if (4 + msgLen < 8) return false
  const nodeMsg = msgType >= 1 && msgType <= 15
  const sessionMsg = msgType >= 50 && msgType <= 57
  if (!nodeMsg && !sessionMsg) return false
  // Session messages carry SEID (S=1); node messages omit it (S=0).
  if (sessionMsg && !sFlag) return false
  if (nodeMsg && sFlag) return false
  const hdrTail = sFlag ? 12 : 4 // after first 4: SEID(8)+seq(4) or seq(4)
  if (msgLen < hdrTail) return false
  return true
}

export function sanitizePfcp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime?: PayloadTimeSession,
  flowEndpoint?: ApplicationFlowEndpoint | null,
  udpPorts?: { readonly srcPort: number; readonly dstPort: number },
): AppLayerResult | null {
  if (!looksLikePfcp(buffer, offset, length)) return null
  const receiveEndpoint = flowEndpoint?.dstIp ?? '?'
  const transportKey = pfcpTransportSessionKey({
    srcIp: flowEndpoint?.srcIp,
    dstIp: flowEndpoint?.dstIp,
    srcPort: udpPorts?.srcPort ?? PFCP_UDP_PORT,
    dstPort: udpPorts?.dstPort ?? PFCP_UDP_PORT,
  })
  const graph = pfcpSessionGraphForTransport(mapping, transportKey)
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  let pos = offset
  const end = offset + length
  let messages = 0

  while (pos < end && messages < MAX_MESSAGES) {
    if (pos + 4 > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'pfcp-trunc')
      coverage.push({ protocol: 'pfcp', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('pfcp-trunc')
      break
    }
    if (!looksLikePfcp(buffer, pos, end - pos)) {
      // Unsupported trailing bundle / foreign trailer — mask remainder explicitly
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'pfcp-bundle-unsupported')
      coverage.push({
        protocol: 'pfcp-bundle',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('pfcp-bundle-unsupported')
      break
    }
    const flags = buffer[pos]!
    const sFlag = (flags >> 0) & 0x1
    const msgLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const msgEnd = pos + 4 + msgLen
    const hdrLen = sFlag ? 16 : 8
    if (pos + hdrLen > msgEnd || msgEnd > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'pfcp-hdr-trunc')
      coverage.push({ protocol: 'pfcp', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('pfcp-hdr-trunc')
      break
    }

    coverage.push({ protocol: 'pfcp', offset: pos, length: hdrLen, status: 'covered' })

    const msgType = buffer[pos + 1]!
    let headerSeidHex: string | null = null
    let generation = 0
    if (sFlag) {
      headerSeidHex = readSeidHex(buffer, pos + 4)
      generation = graph.resolveGeneration(headerSeidHex, msgType)
      mapSeidBytes(buffer, pos + 4, collector, mapping, intents, packetIndex, {
        receiveEndpoint,
        generation,
        associationEpoch: graph.currentAssociationEpoch(),
        role: 'hdr',
        headerSeidHex,
      })
    }
    const msgCtx: PfcpMessageContext = {
      receiveEndpoint,
      generation,
      msgType,
      headerSeidHex,
      graph,
    }

    walkIes(
      buffer,
      pos + hdrLen,
      msgEnd - (pos + hdrLen),
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
      0,
      payloadTime,
      msgCtx,
    )

    if (sFlag && headerSeidHex) {
      graph.noteSessionEnd(headerSeidHex, msgType)
    }

    pos = msgEnd
    messages += 1
  }

  if (pos < end && messages >= MAX_MESSAGES) {
    maskSpan(collector, intents, packetIndex, pos, end - pos, 'pfcp-msg-cap')
    coverage.push({ protocol: 'pfcp-bundle', offset: pos, length: end - pos, status: 'redacted' })
    issues.push('pfcp-msg-cap')
  }

  return { coverage, issues }
}

function walkIes(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  depth: number,
  payloadTime: PayloadTimeSession | undefined,
  msgCtx: PfcpMessageContext,
): void {
  if (depth >= MAX_IE_DEPTH) {
    maskSpan(collector, intents, packetIndex, offset, length, 'pfcp-ie-depth')
    coverage.push({ protocol: 'pfcp-ie', offset, length, status: 'redacted' })
    issues.push('pfcp-ie-depth')
    return
  }
  let pos = offset
  const end = offset + length
  while (pos + 4 <= end) {
    const type = (buffer[pos]! << 8) | buffer[pos + 1]!
    const ieLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const enterprise = (type & 0x8000) !== 0
    let valueOff = pos + 4
    let valueLen = ieLen
    if (enterprise) {
      if (ieLen < 4 || valueOff + ieLen > end) {
        maskSpan(collector, intents, packetIndex, pos, end - pos, 'pfcp-ent-trunc')
        coverage.push({ protocol: 'pfcp-ie', offset: pos, length: end - pos, status: 'malformed' })
        issues.push('pfcp-ent-trunc')
        return
      }
      // Vendor ID (4) + opaque value — preserve type/len/vendor, mask payload
      if (ieLen > 4) {
        maskSpan(collector, intents, packetIndex, valueOff + 4, ieLen - 4, 'pfcp-enterprise')
        coverage.push({
          protocol: 'pfcp-enterprise',
          offset: pos,
          length: 4 + ieLen,
          status: 'redacted',
        })
      } else {
        coverage.push({ protocol: 'pfcp-enterprise', offset: pos, length: 4 + ieLen, status: 'covered' })
      }
      pos = valueOff + ieLen
      continue
    }
    if (valueOff + ieLen > end) {
      maskSpan(collector, intents, packetIndex, pos, end - pos, 'pfcp-ie-trunc')
      coverage.push({ protocol: 'pfcp-ie', offset: pos, length: end - pos, status: 'malformed' })
      issues.push('pfcp-ie-trunc')
      return
    }
    // CF-09: type/length octets must be covered or exportBoundary masks the whole IE body
    // (including already-mapped SEID/F-TEID), destroying stable wire aliases (V13).
    coverage.push({ protocol: 'pfcp-ie-hdr', offset: pos, length: 4, status: 'covered' })
    sanitizeIe(
      buffer,
      type,
      valueOff,
      valueLen,
      collector,
      mapping,
      intents,
      packetIndex,
      coverage,
      issues,
      depth,
      payloadTime,
      msgCtx,
    )
    pos = valueOff + ieLen
  }
  if (pos < end) {
    maskSpan(collector, intents, packetIndex, pos, end - pos, 'pfcp-ie-tail')
    coverage.push({ protocol: 'pfcp-ie-tail', offset: pos, length: end - pos, status: 'redacted' })
  }
}

function sanitizeIe(
  buffer: Uint8Array,
  type: number,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  depth: number,
  payloadTime: PayloadTimeSession | undefined,
  msgCtx: PfcpMessageContext,
): void {
  if (GROUPED.has(type)) {
    walkIes(
      buffer, abs, len, collector, mapping, intents, packetIndex, coverage, issues, depth + 1, payloadTime, msgCtx,
    )
    return
  }
  switch (type) {
    case IE.F_TEID:
      mapFteid(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'pfcp-f-teid', offset: abs, length: len, status: 'covered' })
      return
    case IE.F_SEID:
      mapFseid(buffer, abs, len, collector, mapping, intents, packetIndex, msgCtx)
      coverage.push({ protocol: 'pfcp-f-seid', offset: abs, length: len, status: 'covered' })
      return
    case IE.NODE_ID:
      mapNodeId(buffer, abs, len, collector, mapping, intents, packetIndex, msgCtx)
      coverage.push({ protocol: 'pfcp-node-id', offset: abs, length: len, status: 'covered' })
      return
    case IE.UE_IP_ADDRESS:
      mapUeIp(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'pfcp-ue-ip', offset: abs, length: len, status: 'covered' })
      return
    case IE.NETWORK_INSTANCE:
    case IE.APN_DNN:
      mapDnsLabels(buffer, abs, len, collector, mapping, intents, packetIndex, 'pfcp-ni')
      coverage.push({ protocol: 'pfcp-network-instance', offset: abs, length: len, status: 'covered' })
      return
    case IE.USER_ID:
      mapUserId(buffer, abs, len, collector, mapping, intents, packetIndex, coverage)
      return
    case IE.OUTER_HEADER_CREATION:
      mapOuterHeaderCreation(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'pfcp-ohc', offset: abs, length: len, status: 'covered' })
      return
    case IE.RECOVERY_TIME_STAMP:
      shiftRecoveryTs(buffer, abs, len, collector, intents, packetIndex, payloadTime, issues, coverage)
      return
    case IE.SDF_FILTER:
    case IE.PFD_CONTENTS:
    case IE.APPLICATION_ID:
    case IE.TRACE_INFORMATION:
      maskSpan(collector, intents, packetIndex, abs, len, `pfcp-ie-${type}`)
      coverage.push({ protocol: 'pfcp-secret', offset: abs, length: len, status: 'redacted' })
      return
    case IE.ALTERNATIVE_SMF_IP:
    case IE.CP_PFCP_ENTITY_IP:
      mapIpAddressIe(buffer, abs, len, collector, mapping, intents, packetIndex)
      coverage.push({ protocol: 'pfcp-ip', offset: abs, length: len, status: 'covered' })
      return
    default:
      if (PRESERVE.has(type)) {
        coverage.push({ protocol: 'pfcp-ie', offset: abs, length: len, status: 'covered' })
        return
      }
      maskSpan(collector, intents, packetIndex, abs, len, `pfcp-ie-${type}`)
      coverage.push({ protocol: 'pfcp-ie', offset: abs, length: len, status: 'redacted' })
  }
}

function readSeidHex(buffer: Uint8Array, offset: number): string {
  return toHex(buffer, offset, 8)
}

/** Header / F-SEID 64-bit SEID → opaque-id (never `teid`). Zero = absent sentinel. */
function mapSeidBytes(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  scope: PfcpSeidScope & { readonly headerSeidHex?: string | null },
): void {
  let allZero = true
  for (let i = 0; i < 8; i++) {
    if (buffer[offset + i] !== 0) {
      allZero = false
      break
    }
  }
  if (allZero) return
  const hex = toHex(buffer, offset, 8)
  const canon = seidMappingCanonical(hex, scope)
  intents?.recordEntityReplacement(packetIndex, offset, 'opaque-id', canon, 8)
  collector.addDeferred(offset, 8, ({ mapping: live }) => {
    try {
      const alias = live.map('opaque-id', canon)
      return seidAliasToBytes(alias)
    } catch {
      return createProtocolNeutralMaskFill({
        length: 8, packetIndex, offset, domain: 'pfcp-seid',
      })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'pfcp', category: 'opaque-id', packetIndex })
  void mapping
  void scope.headerSeidHex
}

/**
 * Collision-aware 64-bit SEID wire encoder. Bytes depend only on the resolved alias
 * (and optional original hex salt), never on packet index / byte offset — same SEID
 * in header and F-SEID must stay identical across the session.
 */
export function encodeSeidWireAlias(alias: string, originalHex?: string): Uint8Array {
  const hexPart = alias.includes(':') ? alias.slice(alias.lastIndexOf(':') + 1) : alias
  const cleaned = hexPart.replace(/[^0-9a-fA-F]/g, '')
  if (cleaned.length >= 16) {
    const out = new Uint8Array(8)
    for (let i = 0; i < 8; i++) {
      out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16)
    }
    if (out.every((b) => b === 0)) out[7] = 1
    return out
  }
  // Non-hex opaque-id aliases (T14 length-stable tokens): FNV-1a → 8 BE octets.
  let h0 = 0x811c9dc5
  let h1 = 0x811c9dc5 ^ 0x9e3779b9
  const material = originalHex ? `${alias}|${originalHex}` : alias
  for (let i = 0; i < material.length; i++) {
    const c = material.charCodeAt(i)
    h0 ^= c
    h0 = Math.imul(h0, 0x01000193) >>> 0
    h1 ^= c ^ ((i + 1) * 17)
    h1 = Math.imul(h1, 0x01000193) >>> 0
  }
  if (h0 === 0 && h1 === 0) h1 = 1
  const out = new Uint8Array(8)
  out[0] = (h0 >>> 24) & 0xff
  out[1] = (h0 >>> 16) & 0xff
  out[2] = (h0 >>> 8) & 0xff
  out[3] = h0 & 0xff
  out[4] = (h1 >>> 24) & 0xff
  out[5] = (h1 >>> 16) & 0xff
  out[6] = (h1 >>> 8) & 0xff
  out[7] = h1 & 0xff
  if (out.every((b) => b === 0)) out[7] = 1
  return out
}

function seidAliasToBytes(alias: string): Uint8Array {
  return encodeSeidWireAlias(alias)
}

function mapFseid(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  msgCtx: PfcpMessageContext,
): void {
  if (len < 9) {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-fseid-short')
    return
  }
  const flags = buffer[abs]!
  const v6 = (flags >> 0) & 0x1
  const v4 = (flags >> 1) & 0x1
  const role = msgCtx.graph.fSeidRoleForMessage(msgCtx.msgType)
  mapSeidBytes(buffer, abs + 1, collector, mapping, intents, packetIndex, {
    receiveEndpoint: msgCtx.receiveEndpoint,
    generation: msgCtx.generation,
    associationEpoch: msgCtx.graph.currentAssociationEpoch(),
    role,
    headerSeidHex: msgCtx.headerSeidHex,
  })
  let pos = abs + 9
  if (v4) {
    if (pos + 4 > abs + len) {
      maskSpan(collector, intents, packetIndex, pos, abs + len - pos, 'pfcp-fseid-v4')
      return
    }
    patchIpv4Bytes(buffer, pos, collector, mapping, intents, packetIndex)
    pos += 4
  }
  if (v6) {
    if (pos + 16 > abs + len) {
      maskSpan(collector, intents, packetIndex, pos, abs + len - pos, 'pfcp-fseid-v6')
      return
    }
    patchIpv6Bytes(buffer, pos, collector, mapping, intents, packetIndex)
  }
}

function mapFteid(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len < 1) {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-fteid-short')
    return
  }
  const flags = buffer[abs]!
  const v4 = (flags >> 0) & 0x1
  const v6 = (flags >> 1) & 0x1
  const ch = (flags >> 2) & 0x1
  const chid = (flags >> 3) & 0x1
  if (ch) {
    // CHOOSE — no TEID/IP present; optional CHOOSE ID
    if (chid && len >= 2) {
      // local choose-id — scoped opaque
      mapOpaqueByte(buffer, abs + 1, 1, 'pfcp-choose-id', collector, mapping, intents, packetIndex)
    }
    return
  }
  if (len < 5) {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-fteid-short')
    return
  }
  // V17 — F-TEID TEID scoped by receive address in the IE.
  let receiveEndpoint = 'pfcp-fteid'
  let peek = abs + 5
  if (v4 && peek + 4 <= abs + len) {
    receiveEndpoint = `${buffer[peek]}.${buffer[peek + 1]}.${buffer[peek + 2]}.${buffer[peek + 3]}`
  } else if (v6 && peek + 16 <= abs + len) {
    const parts: string[] = []
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buffer[peek + i]! << 8) | buffer[peek + i + 1]!).toString(16))
    }
    receiveEndpoint = parts.join(':')
  }
  patchTeid(buffer, abs + 1, collector, mapping, intents, packetIndex, {
    receiveEndpoint,
    plane: 'u',
  })
  let pos = abs + 5
  if (v4) {
    if (pos + 4 > abs + len) {
      maskSpan(collector, intents, packetIndex, pos, abs + len - pos, 'pfcp-fteid-v4')
      return
    }
    patchIpv4Bytes(buffer, pos, collector, mapping, intents, packetIndex)
    pos += 4
  }
  if (v6) {
    if (pos + 16 > abs + len) {
      maskSpan(collector, intents, packetIndex, pos, abs + len - pos, 'pfcp-fteid-v6')
      return
    }
    patchIpv6Bytes(buffer, pos, collector, mapping, intents, packetIndex)
  }
}

function mapNodeId(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  msgCtx: PfcpMessageContext,
): void {
  if (len < 1) {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-node-short')
    return
  }
  const nodeType = buffer[abs]! & 0x0f
  const valOff = abs + 1
  const valLen = len - 1
  // Association Setup (5/6) and Update (7/8) carry Node ID — track SMF identity for failover.
  if (msgCtx.msgType >= 5 && msgCtx.msgType <= 8) {
    const nodeKey = pfcpNodeKey(buffer, abs, len)
    if (nodeKey) msgCtx.graph.noteAssociationNode(nodeKey)
  }
  if (nodeType === 0 && valLen === 4) {
    patchIpv4Bytes(buffer, valOff, collector, mapping, intents, packetIndex)
  } else if (nodeType === 1 && valLen === 16) {
    patchIpv6Bytes(buffer, valOff, collector, mapping, intents, packetIndex)
  } else if (nodeType === 2 && valLen > 0) {
    mapDnsLabels(buffer, valOff, valLen, collector, mapping, intents, packetIndex, 'pfcp-node-fqdn')
  } else {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-node-unknown')
  }
}

/** Stable Node ID key for association-epoch failover (not the mapped alias). */
function pfcpNodeKey(buffer: Uint8Array, abs: number, len: number): string | null {
  if (len < 1) return null
  const nodeType = buffer[abs]! & 0x0f
  const valOff = abs + 1
  const valLen = len - 1
  if (nodeType === 0 && valLen === 4) {
    return `v4:${buffer[valOff]!}.${buffer[valOff + 1]!}.${buffer[valOff + 2]!}.${buffer[valOff + 3]!}`
  }
  if (nodeType === 1 && valLen === 16) {
    return `v6:${toHex(buffer, valOff, 16)}`
  }
  if (nodeType === 2 && valLen > 0) {
    return `fqdn:${toHex(buffer, valOff, valLen)}`
  }
  return `raw:${nodeType}:${toHex(buffer, abs, len)}`
}

function mapUeIp(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len < 1) return
  const flags = buffer[abs]!
  // Bit1 V6, Bit2 V4, Bit3 S/D, Bit4 IPv6D, Bit5 IP6PL — map present addresses
  const v6 = (flags >> 0) & 0x1
  const v4 = (flags >> 1) & 0x1
  let pos = abs + 1
  if (v4) {
    if (pos + 4 > abs + len) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-ueip-v4')
      return
    }
    patchIpv4Bytes(buffer, pos, collector, mapping, intents, packetIndex)
    pos += 4
  }
  if (v6) {
    if (pos + 16 > abs + len) {
      maskSpan(collector, intents, packetIndex, pos, abs + len - pos, 'pfcp-ueip-v6')
      return
    }
    patchIpv6Bytes(buffer, pos, collector, mapping, intents, packetIndex)
  }
}

/**
 * Outer Header Creation (IE 84): description(2) + optional TEID + IPv4/IPv6 + port…
 * Description bits: GTPU/UDP/IP etc. Baseline maps TEID + IP when present.
 */
function mapOuterHeaderCreation(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len < 2) {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-ohc-short')
    return
  }
  const desc = (buffer[abs]! << 8) | buffer[abs + 1]!
  // Bit 0 GTP-U/UDP/IPv4, bit 1 GTP-U/UDP/IPv6, bit 2 UDP/IPv4, bit 3 UDP/IPv6, …
  const gtpU = (desc & 0x0003) !== 0
  const v4 = (desc & 0x0005) !== 0 // bits involving IPv4 outer
  const v6 = (desc & 0x000a) !== 0
  let pos = abs + 2
  if (gtpU) {
    if (pos + 4 > abs + len) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-ohc-teid')
      return
    }
    // R07 — TEID scope needs a real receive endpoint. Never share a fake key (e.g. "pfcp-ohc")
    // across unrelated sessions when outer IP is truncated/absent — mask fail-closed instead.
    let receiveEndpoint: string | undefined
    const afterTeid = pos + 4
    if (v4 && (desc & 0x0001 || desc & 0x0004) && afterTeid + 4 <= abs + len) {
      receiveEndpoint =
        `${buffer[afterTeid]}.${buffer[afterTeid + 1]}.${buffer[afterTeid + 2]}.${buffer[afterTeid + 3]}`
    } else if (v6 && (desc & 0x0002 || desc & 0x0008) && afterTeid + 16 <= abs + len) {
      const parts: string[] = []
      for (let i = 0; i < 16; i += 2) {
        parts.push(((buffer[afterTeid + i]! << 8) | buffer[afterTeid + i + 1]!).toString(16))
      }
      receiveEndpoint = parts.join(':')
    }
    if (!receiveEndpoint) {
      maskSpan(collector, intents, packetIndex, pos, 4, 'pfcp-ohc-teid-unscoped')
    } else {
      patchTeid(buffer, pos, collector, mapping, intents, packetIndex, {
        receiveEndpoint,
        plane: 'u',
      })
    }
    pos += 4
  }
  if (v4 && (desc & 0x0001 || desc & 0x0004)) {
    if (pos + 4 <= abs + len) {
      patchIpv4Bytes(buffer, pos, collector, mapping, intents, packetIndex)
      pos += 4
    }
  }
  if (v6 && (desc & 0x0002 || desc & 0x0008)) {
    if (pos + 16 <= abs + len) {
      patchIpv6Bytes(buffer, pos, collector, mapping, intents, packetIndex)
      pos += 16
    }
  }
  // Remaining port / VLAN / opaque — mask (may carry identifiers)
  if (pos < abs + len) {
    maskSpan(collector, intents, packetIndex, pos, abs + len - pos, 'pfcp-ohc-tail')
  }
}

/** User ID: flags + length-prefixed IMSI/IMEI/MSISDN/NAI (TS 29.244 8.2.101). */
function mapUserId(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  if (len < 1) return
  const flags = buffer[abs]!
  const imsiF = (flags >> 0) & 0x1
  const imeiF = (flags >> 1) & 0x1
  const msisdnF = (flags >> 2) & 0x1
  const naiF = (flags >> 3) & 0x1
  let pos = abs + 1
  const end = abs + len
  if (imsiF) {
    if (pos >= end) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-userid-trunc')
      return
    }
    const l = buffer[pos]!
    pos += 1
    if (pos + l > end) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-userid-imsi')
      return
    }
    mapTbcdCategory(buffer, pos, l, 'imsi', collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'pfcp-imsi', offset: pos, length: l, status: 'covered' })
    pos += l
  }
  if (imeiF) {
    if (pos >= end) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-userid-trunc')
      return
    }
    const l = buffer[pos]!
    pos += 1
    if (pos + l > end) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-userid-imei')
      return
    }
    mapTbcdCategory(buffer, pos, l, 'imei', collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'pfcp-imei', offset: pos, length: l, status: 'covered' })
    pos += l
  }
  if (msisdnF) {
    if (pos >= end) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-userid-trunc')
      return
    }
    const l = buffer[pos]!
    pos += 1
    if (pos + l > end) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-userid-msisdn')
      return
    }
    mapMsisdn(buffer, pos, l, collector, mapping, intents, packetIndex)
    coverage.push({ protocol: 'pfcp-msisdn', offset: pos, length: l, status: 'covered' })
    pos += l
  }
  if (naiF) {
    if (pos >= end) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-userid-trunc')
      return
    }
    const l = buffer[pos]!
    pos += 1
    if (pos + l > end) {
      maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-userid-nai')
      return
    }
    maskSpan(collector, intents, packetIndex, pos, l, 'pfcp-nai')
    coverage.push({ protocol: 'pfcp-nai', offset: pos, length: l, status: 'redacted' })
    pos += l
  }
  if (pos < end) {
    maskSpan(collector, intents, packetIndex, pos, end - pos, 'pfcp-userid-tail')
  }
}

function shiftRecoveryTs(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  payloadTime: PayloadTimeSession | undefined,
  issues: string[],
  coverage: LayerCoverage[],
): void {
  if (len < 4) {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-recovery-short')
    coverage.push({ protocol: 'pfcp-recovery', offset: abs, length: len, status: 'malformed' })
    return
  }
  const sec =
    (BigInt(buffer[abs]!) << 24n)
    | (BigInt(buffer[abs + 1]!) << 16n)
    | (BigInt(buffer[abs + 2]!) << 8n)
    | BigInt(buffer[abs + 3]!)
  if (sec === 0n) {
    coverage.push({ protocol: 'pfcp-recovery', offset: abs, length: 4, status: 'covered' })
    return
  }
  if (!payloadTime?.isBound) {
    maskSpan(collector, intents, packetIndex, abs, 4, 'pfcp-recovery-unbound')
    coverage.push({ protocol: 'pfcp-recovery', offset: abs, length: 4, status: 'redacted' })
    issues.push('pfcp-recovery-unbound')
    return
  }
  if (sec < NTP_UNIX_DELTA) {
    maskSpan(collector, intents, packetIndex, abs, 4, 'pfcp-recovery-era')
    coverage.push({ protocol: 'pfcp-recovery', offset: abs, length: 4, status: 'redacted' })
    issues.push('pfcp-recovery-era')
    return
  }
  const unixSec = sec - NTP_UNIX_DELTA
  if (unixSec > BigInt(Number.MAX_SAFE_INTEGER)) {
    maskSpan(collector, intents, packetIndex, abs, 4, 'pfcp-recovery-overflow')
    coverage.push({ protocol: 'pfcp-recovery', offset: abs, length: 4, status: 'redacted' })
    return
  }
  const shiftedMs = payloadTime.shiftAbsoluteEpochMs(Number(unixSec) * 1000)
  if (shiftedMs === null) {
    maskSpan(collector, intents, packetIndex, abs, 4, 'pfcp-recovery-unwritable')
    coverage.push({ protocol: 'pfcp-recovery', offset: abs, length: 4, status: 'redacted' })
    return
  }
  const shiftedNtp = BigInt(Math.trunc(shiftedMs / 1000)) + NTP_UNIX_DELTA
  if (shiftedNtp < 0n || shiftedNtp > 0xffffffffn) {
    maskSpan(collector, intents, packetIndex, abs, 4, 'pfcp-recovery-range')
    coverage.push({ protocol: 'pfcp-recovery', offset: abs, length: 4, status: 'redacted' })
    return
  }
  const s = Number(shiftedNtp & 0xffffffffn)
  collector.addDeferred(abs, 4, () => new Uint8Array([
    (s >>> 24) & 0xff,
    (s >>> 16) & 0xff,
    (s >>> 8) & 0xff,
    s & 0xff,
  ]))
  coverage.push({ protocol: 'pfcp-recovery', offset: abs, length: 4, status: 'covered' })
  if (len > 4) {
    maskSpan(collector, intents, packetIndex, abs + 4, len - 4, 'pfcp-recovery-ext')
  }
}

function mapTbcdCategory(
  buffer: Uint8Array,
  abs: number,
  len: number,
  category: 'imsi' | 'imei',
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len <= 0) return
  const slice = buffer.subarray(abs, abs + len)
  const digits = decodeTbcd(slice, TBCD_GSM)
  if (!digits) {
    maskSpan(collector, intents, packetIndex, abs, len, `pfcp-${category}-bad`)
    return
  }
  const normalized = category === 'imsi' ? normalizeImsiDigits(digits) : normalizeImeiDigits(digits)
  const canon = normalized ? canonicalizeIdentity(category, normalized) : null
  if (!canon) {
    maskSpan(collector, intents, packetIndex, abs, len, `pfcp-${category}-bad`)
    return
  }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const alias = live.map(category, canon)
      const remapped = remapTbcdBytes(slice, alias, TBCD_GSM)
      if (remapped) return remapped
      const encoded = encodeTbcd(alias, len, TBCD_GSM)
      if (encoded) return encoded
    } catch { /* fall through */ }
    return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `pfcp-${category}` })
  }, { fallbackKind: 'binary-mask', protocol: 'pfcp', category, packetIndex })
  void mapping
}

function mapMsisdn(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  // Optional TON/NPI + TBCD — map digits, preserve first byte when present
  if (len <= 0) return
  let digitOff = abs
  let digitLen = len
  if (len > 1 && (buffer[abs]! & 0x80) !== 0) {
    digitOff = abs + 1
    digitLen = len - 1
  }
  const slice = buffer.subarray(digitOff, digitOff + digitLen)
  const digits = decodeTbcd(slice, TBCD_GSM)
  if (!digits) {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-msisdn-bad')
    return
  }
  const canon = canonicalizeIdentity('sip-phone', digits)
  if (!canon) {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-msisdn-bad')
    return
  }
  intents?.recordEntityReplacement(packetIndex, digitOff, 'sip-phone', canon, digitLen)
  collector.addDeferred(digitOff, digitLen, ({ mapping: live }) => {
    try {
      const alias = live.map('sip-phone', canon)
      const remapped = remapTbcdBytes(slice, alias.replace(/\D/g, ''), TBCD_GSM)
      if (remapped) return remapped
      const encoded = encodeTbcd(alias.replace(/\D/g, ''), digitLen, TBCD_GSM)
      if (encoded) return encoded
    } catch { /* fall through */ }
    return createProtocolNeutralMaskFill({
      length: digitLen, packetIndex, offset: digitOff, domain: 'pfcp-msisdn',
    })
  }, { fallbackKind: 'binary-mask', protocol: 'pfcp', category: 'sip-phone', packetIndex })
  void mapping
}

function mapDnsLabels(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  if (len <= 0) return
  // Heuristic: length-prefixed DNS labels vs opaque octet string
  const first = buffer[abs]!
  if (first === 0 || first >= len) {
    maskSpan(collector, intents, packetIndex, abs, len, domain)
    return
  }
  const labels: { offset: number; length: number; text: string }[] = []
  let cur = 0
  while (cur < len) {
    const labelLen = buffer[abs + cur]!
    if (labelLen === 0) break
    if (cur + 1 + labelLen > len) {
      maskSpan(collector, intents, packetIndex, abs, len, `${domain}-trunc`)
      return
    }
    let text = ''
    for (let i = 0; i < labelLen; i++) {
      const c = buffer[abs + cur + 1 + i]!
      if (c < 0x20 || c > 0x7e) {
        maskSpan(collector, intents, packetIndex, abs, len, `${domain}-bin`)
        return
      }
      text += String.fromCharCode(c)
    }
    labels.push({ offset: cur + 1, length: labelLen, text: text.toLowerCase() })
    cur += 1 + labelLen
  }
  if (labels.length === 0) {
    maskSpan(collector, intents, packetIndex, abs, len, `${domain}-empty`)
    return
  }
  const fullName = labels.map((l) => l.text).join('.')
  const canon = canonicalizeIdentity('hostname', fullName)
  if (!canon) {
    maskSpan(collector, intents, packetIndex, abs, len, `${domain}-bad`)
    return
  }
  const firstAbs = abs + labels[0]!.offset
  intents?.recordEntityReplacement(packetIndex, firstAbs, 'hostname', canon, labels[0]!.length)
  for (let i = 0; i < labels.length; i++) {
    const label = labels[i]!
    const labelAbs = abs + label.offset
    collector.addDeferred(labelAbs, label.length, ({ mapping: live }) => {
      try {
        const mappedLabels = live.map('hostname', canon).split('.')
        const mapped = mappedLabels[i] ?? 'x'.repeat(label.length)
        return computeFixedLengthAsciiBytes(labelAbs, label.length, mapped)
      } catch {
        return createProtocolNeutralMaskFill({
          length: label.length, packetIndex, offset: labelAbs, domain,
        })
      }
    }, { fallbackKind: 'text-x', protocol: 'pfcp', category: 'hostname', packetIndex })
  }
  void mapping
}

function mapIpAddressIe(
  buffer: Uint8Array,
  abs: number,
  len: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  // Flags byte optional in some IEs — try raw 4/16 first
  if (len === 4) {
    patchIpv4Bytes(buffer, abs, collector, mapping, intents, packetIndex)
  } else if (len === 16) {
    patchIpv6Bytes(buffer, abs, collector, mapping, intents, packetIndex)
  } else if (len === 5 && (buffer[abs]! & 0x03) !== 0) {
    patchIpv4Bytes(buffer, abs + 1, collector, mapping, intents, packetIndex)
  } else if (len === 17 && (buffer[abs]! & 0x03) !== 0) {
    patchIpv6Bytes(buffer, abs + 1, collector, mapping, intents, packetIndex)
  } else if (len > 0) {
    maskSpan(collector, intents, packetIndex, abs, len, 'pfcp-ip-ie')
  }
}

function mapOpaqueByte(
  buffer: Uint8Array,
  abs: number,
  len: number,
  domain: string,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (len <= 0) return
  const hex = toHex(buffer, abs, len)
  const canon = canonicalizeIdentity('opaque-id', `${domain}:${hex}`) ?? `${domain}:${hex}`
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: len, packetIndex, offset: abs, domain: `${domain}:${alias}`,
    })
  })
  void mapping
  void buffer
}

function patchIpv4Bytes(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const ip = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`
  if (ip === '0.0.0.0') return
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv4', ip, 4)
  collector.addDeferred(offset, 4, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.map('ipv4', ip)
    return new Uint8Array(mapped.split('.').map(Number))
  }, deferredBinaryMapMeta('pfcp', packetIndex, 'ipv4', ip))
}

function patchIpv6Bytes(
  buffer: Uint8Array,
  offset: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const parts: string[] = []
  for (let i = 0; i < 16; i += 2) {
    parts.push(((buffer[offset + i]! << 8) | buffer[offset + i + 1]!).toString(16))
  }
  const ip = parts.join(':')
  intents?.recordEntityReplacement(packetIndex, offset, 'ipv6', ip, 16)
  collector.addDeferred(offset, 16, ({ mapping: liveMapping }) => {
    const mapped = liveMapping.map('ipv6', ip)
    const out = new Uint8Array(16)
    const hex = mapped.replace(/:/g, '')
    if (hex.length === 32) {
      for (let i = 0; i < 16; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
      }
      return out
    }
    const groups = mapped.split(':')
    let idx = 0
    for (const g of groups) {
      if (g === '' || idx >= 16) continue
      const val = parseInt(g, 16)
      out[idx++] = (val >> 8) & 0xff
      out[idx++] = val & 0xff
    }
    return out
  }, deferredBinaryMapMeta('pfcp', packetIndex, 'ipv6', ip))
}

function maskSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  domain: string,
): void {
  if (length <= 0) return
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'pfcp')
  collector.addDeferred(offset, length, () => createProtocolNeutralMaskFill({
    length, packetIndex, offset, domain,
  }))
}

function toHex(buf: Uint8Array, offset: number, length: number): string {
  let s = ''
  for (let i = 0; i < length; i++) {
    s += buf[offset + i]!.toString(16).padStart(2, '0')
  }
  return s
}
