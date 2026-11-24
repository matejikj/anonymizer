/**
 * T51 — QSIG Facility ROSE sanitizer (pinned ECMA-143/165 operation dictionary baseline).
 * Preserves ROSE invoke/result envelopes + invokeId/opcode; maps identity-bearing argument leaves.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { LayerCoverage } from '../types.ts'
import { walkBer, type BerNode } from '../../protocols/application/binproto/ber.ts'
import {
  QSIG_FACILITY_TAG,
  qsigPinnedOperation,
  type QsigPinnedOperation,
} from '../../protocols/application/qsig/index.ts'
import { decodeTbcd, TBCD_GSM } from '../../protocols/application/binproto/tbcd.ts'
import { maskPayloadSpan } from '../../protocols/application/textproto'
import { mapQ931AsciiField, mapQ931PartyDigits } from './q931IdentityFields.ts'

const MAX_BER_DEPTH = 14
const MAX_BER_NODES = 192

export interface QsigFacilitySanitizeResult {
  readonly coverage: LayerCoverage[]
  readonly issues: string[]
  /** false → caller should fail-closed mask entire Facility payload (non-BER / legacy). */
  readonly structured: boolean
}

export function sanitizeQsigFacilityRose(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  identityScopePrefix: string,
): QsigFacilitySanitizeResult {
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  if (length <= 0) {
    return { coverage, issues, structured: false }
  }

  const walked = walkBer(buffer, offset, length, {
    maxDepth: MAX_BER_DEPTH,
    maxNodes: MAX_BER_NODES,
    allowIndefinite: false,
  })
  if (walked.roots.length === 0) {
    return { coverage, issues, structured: false }
  }

  let sawQsigApdu = false
  for (const root of walked.roots) {
    if (visitFacilityApdu(
      buffer,
      root,
      collector,
      mapping,
      intents,
      packetIndex,
      protocolPrefix,
      identityScopePrefix,
      coverage,
      issues,
      0,
    )) {
      sawQsigApdu = true
    }
  }

  if (!sawQsigApdu) {
    return { coverage, issues, structured: false }
  }

  coverage.push({
    protocol: `${protocolPrefix}-facility`,
    offset,
    length,
    status: 'covered',
  })
  return { coverage, issues, structured: true }
}

function visitFacilityApdu(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  identityScopePrefix: string,
  coverage: LayerCoverage[],
  issues: string[],
  depth: number,
): boolean {
  if (depth > MAX_BER_DEPTH) return false
  const tag = node.tag
  if (tag.tagClass !== 'context') return false

  if (tag.number === QSIG_FACILITY_TAG.INTERPRETATION) {
    coverage.push({
      protocol: `${protocolPrefix}-qsig-interpretation`,
      offset: tag.headerOffset,
      length: node.contentLength + tag.headerLength + node.length.headerLength,
      status: 'covered',
    })
    return true
  }

  if (tag.number === QSIG_FACILITY_TAG.NFE) {
    coverage.push({
      protocol: `${protocolPrefix}-qsig-nfe`,
      offset: tag.headerOffset,
      length: tag.headerLength + node.length.headerLength + node.contentLength,
      status: 'covered',
    })
    sanitizeIdentityLeavesInTree(
      buffer,
      node,
      collector,
      mapping,
      intents,
      packetIndex,
      protocolPrefix,
      identityScopePrefix,
      coverage,
      issues,
      depth + 1,
      'nfe',
    )
    return true
  }

  if (tag.number === QSIG_FACILITY_TAG.ROSE_INVOKE && tag.constructed) {
    return sanitizeRoseInvoke(
      buffer,
      node,
      collector,
      mapping,
      intents,
      packetIndex,
      protocolPrefix,
      identityScopePrefix,
      coverage,
      issues,
    )
  }

  if (
    tag.number === QSIG_FACILITY_TAG.ROSE_RETURN_RESULT
    || tag.number === QSIG_FACILITY_TAG.ROSE_RETURN_ERROR
  ) {
    const pinned = tag.number === QSIG_FACILITY_TAG.ROSE_RETURN_RESULT
    coverage.push({
      protocol: `${protocolPrefix}-qsig-rose-${pinned ? 'result' : 'error'}`,
      offset: tag.headerOffset,
      length: tag.headerLength + node.length.headerLength + node.contentLength,
      status: 'covered',
    })
    sanitizeIdentityLeavesInTree(
      buffer,
      node,
      collector,
      mapping,
      intents,
      packetIndex,
      protocolPrefix,
      identityScopePrefix,
      coverage,
      issues,
      depth + 1,
      'result',
    )
    return true
  }

  if (tag.number === QSIG_FACILITY_TAG.ROSE_REJECT) {
    coverage.push({
      protocol: `${protocolPrefix}-qsig-rose-reject`,
      offset: tag.headerOffset,
      length: tag.headerLength + node.length.headerLength + node.contentLength,
      status: 'covered',
    })
    return true
  }

  return false
}

function sanitizeRoseInvoke(
  buffer: Uint8Array,
  invokeNode: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  identityScopePrefix: string,
  coverage: LayerCoverage[],
  issues: string[],
): boolean {
  const absOff = invokeNode.tag.headerOffset
  const absLen =
    invokeNode.tag.headerLength + invokeNode.length.headerLength + invokeNode.contentLength
  coverage.push({
    protocol: `${protocolPrefix}-qsig-rose-invoke`,
    offset: absOff,
    length: absLen,
    status: 'covered',
  })

  const { opcode, argumentNode } = extractInvokeFields(buffer, invokeNode)
  if (opcode === undefined) {
    issues.push(`${protocolPrefix}-qsig-rose-opcode-missing`)
    if (argumentNode) {
      maskSpan(
        collector,
        intents,
        packetIndex,
        argumentNode.contentOffset,
        argumentNode.contentLength,
        protocolPrefix,
        coverage,
        `${protocolPrefix}-qsig-rose-arg`,
      )
    }
    return true
  }

  coverage.push({
    protocol: `${protocolPrefix}-qsig-rose-opcode`,
    offset: absOff,
    length: absLen,
    status: 'covered',
  })

  const pinned = qsigPinnedOperation(opcode)
  if (!argumentNode || argumentNode.contentLength <= 0) {
    if (!pinned) issues.push(`${protocolPrefix}-qsig-rose-unknown-op`)
    return true
  }

  if (!pinned) {
    maskSpan(
      collector,
      intents,
      packetIndex,
      argumentNode.contentOffset,
      argumentNode.contentLength,
      protocolPrefix,
      coverage,
      `${protocolPrefix}-qsig-rose-arg`,
    )
    issues.push(`${protocolPrefix}-qsig-rose-unknown-op`)
    return true
  }

  sanitizePinnedArgument(
    buffer,
    argumentNode,
    pinned,
    collector,
    mapping,
    intents,
    packetIndex,
    protocolPrefix,
    identityScopePrefix,
    coverage,
    issues,
  )
  return true
}

function extractInvokeFields(
  buffer: Uint8Array,
  invokeNode: BerNode,
): { readonly opcode?: number; readonly argumentNode?: BerNode } {
  const children = invokeNode.children
  if (children.length === 0) return {}

  let opcode: number | undefined
  let argumentNode: BerNode | undefined
  let seenInvokeId = false

  for (const child of children) {
    if (
      !seenInvokeId
      && child.tag.tagClass === 'universal'
      && child.tag.number === 2
      && !child.tag.constructed
    ) {
      seenInvokeId = true
      continue
    }
    const op = readOperationCodeFromNode(buffer, child)
    if (op !== undefined) {
      opcode = op
      continue
    }
    if (argumentNode === undefined && child.contentLength > 0) {
      argumentNode = child
    }
  }
  return { opcode, argumentNode }
}

function readBerInteger(buffer: Uint8Array, node: BerNode): number | undefined {
  if (node.contentLength <= 0 || node.contentLength > 4) return undefined
  let v = 0
  for (let i = 0; i < node.contentLength; i++) {
    v = (v << 8) | buffer[node.contentOffset + i]!
  }
  return v
}

function readOperationCodeFromNode(buffer: Uint8Array, node: BerNode): number | undefined {
  if (node.tag.tagClass === 'universal' && node.tag.number === 2 && !node.tag.constructed) {
    return readBerInteger(buffer, node)
  }
  if (node.tag.tagClass === 'context' && node.tag.number === 0 && !node.tag.constructed) {
    return readBerInteger(buffer, node)
  }
  if (node.tag.constructed && node.children.length === 1) {
    return readOperationCodeFromNode(buffer, node.children[0]!)
  }
  return undefined
}

function sanitizePinnedArgument(
  buffer: Uint8Array,
  argumentNode: BerNode,
  pinned: QsigPinnedOperation,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  identityScopePrefix: string,
  coverage: LayerCoverage[],
  issues: string[],
): void {
  coverage.push({
    protocol: `${protocolPrefix}-qsig-rose-arg`,
    offset: argumentNode.contentOffset,
    length: argumentNode.contentLength,
    status: 'covered',
  })
  sanitizeIdentityLeavesInTree(
    buffer,
    argumentNode,
    collector,
    mapping,
    intents,
    packetIndex,
    protocolPrefix,
    identityScopePrefix,
    coverage,
    issues,
    0,
    pinned.role,
  )
  void issues
}

function sanitizeIdentityLeavesInTree(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  identityScopePrefix: string,
  coverage: LayerCoverage[],
  issues: string[],
  depth: number,
  role: QsigPinnedOperation['role'] | 'nfe' | 'result',
): void {
  if (depth > MAX_BER_DEPTH) return

  if (node.tag.constructed && node.children.length > 0) {
    for (const child of node.children) {
      sanitizeIdentityLeavesInTree(
        buffer,
        child,
        collector,
        mapping,
        intents,
        packetIndex,
        protocolPrefix,
        identityScopePrefix,
        coverage,
        issues,
        depth + 1,
        role,
      )
    }
    return
  }

  const off = node.contentOffset
  const len = node.contentLength
  if (len <= 0) return

  const uni = node.tag.tagClass === 'universal' ? node.tag.number : -1
  const isString =
    uni === 4
    || uni === 12
    || uni === 19
    || uni === 20
    || uni === 22
    || (node.tag.tagClass === 'context' && !node.tag.constructed && len >= 2)

  if (!isString) {
    if (uni === 2 || uni === 10) {
      coverage.push({
        protocol: `${protocolPrefix}-qsig-rose-preserve`,
        offset: off,
        length: len,
        status: 'covered',
      })
    }
    return
  }

  if (tryPartyNumber(buffer, off, len, collector, mapping, intents, packetIndex, protocolPrefix, identityScopePrefix, coverage)) {
    return
  }

  const personLike = role === 'name' || role === 'nfe'
  if (looksLikePersonText(buffer, off, len)) {
    mapQ931AsciiField(
      buffer,
      off,
      len,
      'person',
      collector,
      mapping,
      intents,
      packetIndex,
      protocolPrefix,
      identityScopePrefix,
      `${identityScopePrefix}qsig-name:`,
    )
    coverage.push({
      protocol: `${protocolPrefix}-qsig-rose-name`,
      offset: off,
      length: len,
      status: 'covered',
    })
    return
  }

  if (looksLikePhoneAscii(buffer, off, len)) {
    mapQ931PartyDigits(
      buffer,
      off,
      len,
      collector,
      mapping,
      intents,
      packetIndex,
      protocolPrefix,
      `${identityScopePrefix}qsig-party:`,
    )
    coverage.push({
      protocol: `${protocolPrefix}-qsig-rose-party`,
      offset: off,
      length: len,
      status: 'covered',
    })
    return
  }

  if (personLike && len >= 4) {
    maskSpan(
      collector,
      intents,
      packetIndex,
      off,
      len,
      protocolPrefix,
      coverage,
      `${protocolPrefix}-qsig-rose-leaf`,
    )
  }
}

function tryPartyNumber(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix: string,
  identityScopePrefix: string,
  coverage: LayerCoverage[],
): boolean {
  if (length < 3) return false
  const hdr = buffer[offset]!
  if ((hdr & 0x80) === 0 && length >= 4) {
    // PartyNumber / ISDN address: type-of-number in high bits of first octet
    const digiOff = offset + 1
    const digiLen = length - 1
    const slice = buffer.subarray(digiOff, digiOff + digiLen)
    const digits = decodeTbcd(slice, TBCD_GSM)
    if (digits && digits.length >= 6 && digits.length <= 15 && /^\d+$/.test(digits)) {
      mapQ931PartyDigits(
        buffer,
        digiOff,
        digiLen,
        collector,
        mapping,
        intents,
        packetIndex,
        protocolPrefix,
        `${identityScopePrefix}qsig-tbcd:`,
      )
      coverage.push({
        protocol: `${protocolPrefix}-qsig-rose-party`,
        offset: digiOff,
        length: digiLen,
        status: 'covered',
      })
      coverage.push({
        protocol: `${protocolPrefix}-qsig-rose-preserve`,
        offset,
        length: 1,
        status: 'covered',
      })
      return true
    }
  }
  return false
}

function looksLikePhoneAscii(buffer: Uint8Array, offset: number, length: number): boolean {
  let digits = 0
  for (let i = 0; i < length; i++) {
    const c = buffer[offset + i]!
    if (c === 0) break
    if (c >= 0x30 && c <= 0x39) digits++
    else if (c !== 0x2b && c !== 0x23 && c !== 0x2a) return false
  }
  return digits >= 6
}

function looksLikePersonText(buffer: Uint8Array, offset: number, length: number): boolean {
  let letters = 0
  for (let i = 0; i < length; i++) {
    const c = buffer[offset + i]!
    if (c === 0) break
    if ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x20) letters++
    else if (c < 0x20 || c > 0x7e) return false
  }
  return letters >= 4
}

function maskSpan(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  offset: number,
  length: number,
  protocolPrefix: string,
  coverage: LayerCoverage[],
  covProtocol: string,
): void {
  if (length <= 0) return
  maskPayloadSpan(collector, offset, length, intents, packetIndex, covProtocol)
  coverage.push({ protocol: covProtocol, offset, length, status: 'redacted' })
  void protocolPrefix
}
