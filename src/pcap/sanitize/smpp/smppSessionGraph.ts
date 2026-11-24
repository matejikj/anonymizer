/**
 * T52 — bounded submit_sm → deliver_sm (DLR) session graph: scoped message_id alias + status facts.
 */

import type { MappingLike } from '../../anonymization/mapping.ts'
import {
  protocolGraphEntry,
  resetProtocolGraphStateRegistryForTests,
} from '../protocolGraphState.ts'

const MAX_PENDING = 4096
const MAX_FACTS = 4096

export interface SmppDlrFact {
  readonly messageId: string
  readonly state?: number
  readonly submitPacketIndex: number
  readonly deliverPacketIndex?: number
}

interface PendingSubmit {
  readonly accountScope: string
  readonly submitPacketIndex: number
}

export class SmppSessionGraph {
  private readonly pending = new Map<string, PendingSubmit>()
  private readonly facts: SmppDlrFact[] = []

  noteSubmit(accountScope: string, messageId: string, packetIndex: number): void {
    if (this.pending.size >= MAX_PENDING) return
    const key = `${accountScope}\0${messageId}`
    if (!this.pending.has(key)) {
      this.pending.set(key, { accountScope, submitPacketIndex: packetIndex })
    }
  }

  noteDeliver(
    accountScope: string,
    messageId: string,
    packetIndex: number,
    state?: number,
  ): SmppDlrFact | null {
    const key = `${accountScope}\0${messageId}`
    const sub = this.pending.get(key)
    if (!sub || sub.accountScope !== accountScope) return null
    this.pending.delete(key)
    const fact: SmppDlrFact = {
      messageId,
      state,
      submitPacketIndex: sub.submitPacketIndex,
      deliverPacketIndex: packetIndex,
    }
    if (this.facts.length < MAX_FACTS) this.facts.push(fact)
    return fact
  }

  getFacts(): readonly SmppDlrFact[] {
    return this.facts
  }
}

export interface SmppTransportSession {
  accountScope: string
  readonly graph: SmppSessionGraph
}

const SMPP_STORE = 'smpp-session'

export function smppTransportSessionForMapping(
  mapping: MappingLike,
  transportSessionKey: string,
): SmppTransportSession {
  return protocolGraphEntry(mapping, `${SMPP_STORE}/${transportSessionKey}`, () => ({
    accountScope: '',
    graph: new SmppSessionGraph(),
  }))
}

/** Prefer smppTransportSessionForMapping via sanitize path. */
export function smppSessionGraphForScope(
  mapping: MappingLike,
  transportSessionKey: string,
): SmppSessionGraph {
  return smppTransportSessionForMapping(mapping, transportSessionKey).graph
}

export function resetSmppSessionGraphsForTests(): void {
  resetProtocolGraphStateRegistryForTests()
}
