/**
 * T60 — PFCP session graph: endpoint-scoped SEID/F-SEID with CP/UP role and generation lifecycle.
 * Association Node ID change (SMF failover) bumps associationEpoch so SEID aliases do not merge
 * across unrelated control-plane identities on the same UDP transport.
 */

import type { MappingLike } from '../../anonymization/mapping.ts'
import { canonicalizeIdentity } from '../../../mapping/canonicalize.ts'
import { protocolGraphEntry } from '../protocolGraphState.ts'

const PFCP_STORE = 'pfcp-session'

export type PfcpSeidRole = 'cp' | 'up' | 'hdr'

export interface PfcpSeidScope {
  readonly receiveEndpoint: string
  readonly role: PfcpSeidRole
  readonly generation: number
  /** Association epoch — increments on Node ID change (failover / new SMF). */
  readonly associationEpoch?: number
}

export function pfcpTransportSessionKey(input: {
  readonly srcIp?: string
  readonly dstIp?: string
  readonly srcPort: number
  readonly dstPort: number
}): string {
  const aIp = input.srcIp ?? '?'
  const bIp = input.dstIp ?? '?'
  const aPort = input.srcPort
  const bPort = input.dstPort
  if (aIp < bIp || (aIp === bIp && aPort <= bPort)) {
    return `pfcp:${aIp}:${aPort}<->${bIp}:${bPort}`
  }
  return `pfcp:${bIp}:${bPort}<->${aIp}:${aPort}`
}

export function seidCanonicalKey(hex: string, scope: PfcpSeidScope): string {
  const epoch = scope.associationEpoch ?? 0
  const raw = `seid|${scope.receiveEndpoint}|${scope.role}|e${epoch}|g${scope.generation}|${hex}`
  return canonicalizeIdentity('opaque-id', raw) ?? raw
}

/** Header SEID shares CP mapping canonical so wire bytes match CP F-SEID (V13). */
export function seidMappingCanonical(hex: string, scope: PfcpSeidScope): string {
  if (scope.role === 'hdr') {
    return seidCanonicalKey(hex, { ...scope, role: 'cp' })
  }
  return seidCanonicalKey(hex, scope)
}

export class PfcpSessionGraph {
  private nextGeneration = 1
  /** Active session generation keyed by header SEID hex on this PFCP transport. */
  private readonly activeByHeaderSeid = new Map<string, number>()
  private associationEpoch = 0
  private lastAssociationNodeKey: string | null = null

  currentAssociationEpoch(): number {
    return this.associationEpoch
  }

  /**
   * Association Setup/Update Node ID. A different Node ID closes open sessions and
   * advances associationEpoch so the same SEID hex does not reuse prior aliases.
   */
  noteAssociationNode(nodeKey: string): void {
    if (this.lastAssociationNodeKey !== null && this.lastAssociationNodeKey !== nodeKey) {
      this.activeByHeaderSeid.clear()
      this.associationEpoch += 1
    }
    this.lastAssociationNodeKey = nodeKey
  }

  resolveGeneration(headerSeidHex: string, msgType: number): number {
    const open = this.activeByHeaderSeid.get(headerSeidHex)
    if (open !== undefined) return open
    if (msgType === 50 || msgType === 54) {
      const gen = this.nextGeneration++
      this.activeByHeaderSeid.set(headerSeidHex, gen)
      return gen
    }
    return 0
  }

  noteSessionEnd(headerSeidHex: string, msgType: number): void {
    if (msgType === 52 || msgType === 56) {
      this.activeByHeaderSeid.delete(headerSeidHex)
    }
  }

  /** F-SEID IE role from session message type (CP in establish req, UP in establish rsp). */
  fSeidRoleForMessage(msgType: number): PfcpSeidRole {
    if (msgType === 54) return 'up'
    if (msgType === 50 || msgType === 51 || msgType === 53) return 'cp'
    return 'cp'
  }
}

export function pfcpSessionGraphForTransport(
  mapping: MappingLike,
  transportSessionKey: string,
): PfcpSessionGraph {
  return protocolGraphEntry(mapping, `${PFCP_STORE}/${transportSessionKey}`, () => new PfcpSessionGraph())
}
