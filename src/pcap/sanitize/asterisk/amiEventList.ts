/**
 * T50 — AMI EventList start/complete correlation (Phase III baseline, bounded).
 */

import type { MappingLike } from '../../anonymization/mapping.ts'
import {
  protocolGraphEntry,
  resetProtocolGraphStateRegistryForTests,
} from '../protocolGraphState.ts'

const MAX_LISTS = 256
const MAX_ITEMS_PER_LIST = 128

export interface AmiEventListState {
  readonly actionId: string
  readonly expected: number
  readonly received: number
  readonly complete: boolean
}

interface EventListRow {
  expected: number
  received: number
  /** Response EventList: Complete seen — finish once received catches up. */
  terminalComplete: boolean
}

export class AmiEventListTracker {
  private readonly lists = new Map<string, EventListRow>()

  start(actionId: string, listItems: number): void {
    if (this.lists.size >= MAX_LISTS) return
    this.lists.set(actionId, {
      expected: Math.min(listItems, MAX_ITEMS_PER_LIST),
      received: 0,
      terminalComplete: false,
    })
  }

  event(actionId: string): AmiEventListState | null {
    const row = this.lists.get(actionId)
    if (!row) return null
    row.received++
    const complete = row.received >= row.expected || row.terminalComplete
    if (complete) this.lists.delete(actionId)
    return {
      actionId,
      expected: row.expected,
      received: row.received,
      complete,
    }
  }

  complete(actionId: string): void {
    const row = this.lists.get(actionId)
    if (!row) return
    row.terminalComplete = true
    if (row.received >= row.expected) this.lists.delete(actionId)
  }
}

const AMI_STORE = 'ami-event-list'

export function amiEventListTrackerForTransport(
  mapping: MappingLike,
  transportSessionKey: string,
): AmiEventListTracker {
  return protocolGraphEntry(mapping, `${AMI_STORE}/${transportSessionKey}`, () => new AmiEventListTracker())
}

/** Prefer transport-scoped tracker via sanitize path. */
export function amiEventListTrackerForSession(
  mapping: MappingLike,
  transportSessionKey: string,
): AmiEventListTracker {
  return amiEventListTrackerForTransport(mapping, transportSessionKey)
}

export function resetAmiEventListTrackersForTests(): void {
  resetProtocolGraphStateRegistryForTests()
}
