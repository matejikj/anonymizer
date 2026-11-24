/**
 * T51 — multi-link Q.931 call graph: merge CR across direction bit + TEI/link scope.
 */

import type { MappingLike } from '../../anonymization/mapping.ts'
import {
  protocolGraphEntry,
  resetProtocolGraphStateRegistryForTests,
} from '../protocolGraphState.ts'

const MAX_CALLS = 8192
const MAX_MESSAGE_TYPES = 32

export interface Q931CallRefKey {
  readonly linkScope: string
  readonly callRef: number
}

export interface Q931CallGraphNode {
  readonly key: Q931CallRefKey
  readonly firstPacketIndex: number
  readonly lastPacketIndex: number
  readonly messageTypes: readonly number[]
}

export interface Q931ObserveResult {
  readonly node: Q931CallGraphNode
  readonly multiLink: boolean
}

export class Q931MultiLinkCallGraph {
  private readonly nodes = new Map<string, Q931CallGraphNode>()
  /** First link scope seen per call reference (multi-link merge detection). */
  private readonly callRefPrimaryLink = new Map<number, string>()

  observe(
    linkScope: string,
    callRefRaw: number,
    msgType: number,
    packetIndex: number,
  ): Q931ObserveResult {
    const callRef = callRefRaw & 0x7fff
    let multiLink = false
    const primary = this.callRefPrimaryLink.get(callRef)
    if (primary !== undefined && primary !== linkScope) {
      multiLink = true
    } else if (primary === undefined && this.callRefPrimaryLink.size < MAX_CALLS) {
      this.callRefPrimaryLink.set(callRef, linkScope)
    }

    const keyStr = `${linkScope}:${callRef}`
    const existing = this.nodes.get(keyStr)
    if (existing) {
      const types = existing.messageTypes.length >= MAX_MESSAGE_TYPES
        ? [...existing.messageTypes.slice(1), msgType]
        : [...existing.messageTypes, msgType]
      const next: Q931CallGraphNode = {
        key: { linkScope, callRef },
        firstPacketIndex: existing.firstPacketIndex,
        lastPacketIndex: packetIndex,
        messageTypes: types,
      }
      this.nodes.set(keyStr, next)
      return { node: next, multiLink }
    }
    if (this.nodes.size >= MAX_CALLS) {
      return {
        node: {
          key: { linkScope, callRef },
          firstPacketIndex: packetIndex,
          lastPacketIndex: packetIndex,
          messageTypes: [msgType],
        },
        multiLink,
      }
    }
    const node: Q931CallGraphNode = {
      key: { linkScope, callRef },
      firstPacketIndex: packetIndex,
      lastPacketIndex: packetIndex,
      messageTypes: [msgType],
    }
    this.nodes.set(keyStr, node)
    return { node, multiLink }
  }
}

const Q931_STORE = 'q931-call-graph'

export function q931CallGraphForMapping(
  mapping: MappingLike,
  captureScopeKey: string,
): Q931MultiLinkCallGraph {
  return protocolGraphEntry(mapping, `${Q931_STORE}/${captureScopeKey}`, () => new Q931MultiLinkCallGraph())
}

/** @deprecated use q931CallGraphForMapping */
export function q931CallGraphForCapture(captureKey: string): Q931MultiLinkCallGraph {
  void captureKey
  return new Q931MultiLinkCallGraph()
}

export function resetQ931CallGraphsForTests(): void {
  resetProtocolGraphStateRegistryForTests()
}
