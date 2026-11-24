/**
 * T49 — MonitorStart/Stop + event lifecycle graph (transport-scoped, bounded).
 */

import type { MappingLike } from '../../anonymization/mapping.ts'
import type { CstaServiceFacts } from '../../protocols/application/csta/cstaXmlFacts.ts'
import {
  protocolGraphEntry,
  resetProtocolGraphStateRegistryForTests,
} from '../protocolGraphState.ts'

const MAX_ACTIVE = 512
const MAX_PENDING_INVOKE = 512
const MAX_FACTS = 1024

export interface CstaMonitorLifecycleFact {
  readonly kind: CstaServiceFacts['kind']
  readonly monitorCrossRefId: string | null
  readonly invokeId: string | null
  readonly packetIndex: number
}

export class CstaMonitorSessionGraph {
  private readonly activeMonitors = new Set<string>()
  private readonly pendingStartByInvoke = new Map<string, { readonly deviceId: string | null; packetIndex: number }>()
  private readonly facts: CstaMonitorLifecycleFact[] = []

  note(facts: CstaServiceFacts, packetIndex: number): void {
    if (this.facts.length < MAX_FACTS) {
      this.facts.push({
        kind: facts.kind,
        monitorCrossRefId: facts.monitorCrossRefId,
        invokeId: facts.invokeId,
        packetIndex,
      })
    }

    switch (facts.kind) {
      case 'monitor-start': {
        if (facts.invokeId && this.pendingStartByInvoke.size < MAX_PENDING_INVOKE) {
          this.pendingStartByInvoke.set(facts.invokeId, {
            deviceId: facts.deviceId,
            packetIndex,
          })
        }
        break
      }
      case 'monitor-start-response': {
        if (facts.monitorCrossRefId && this.activeMonitors.size < MAX_ACTIVE) {
          this.activeMonitors.add(facts.monitorCrossRefId)
        }
        if (facts.invokeId) this.pendingStartByInvoke.delete(facts.invokeId)
        break
      }
      case 'monitor-stop': {
        if (facts.monitorCrossRefId) this.activeMonitors.delete(facts.monitorCrossRefId)
        break
      }
      case 'monitor-event': {
        if (facts.monitorCrossRefId && this.activeMonitors.size < MAX_ACTIVE) {
          // Event may arrive before MonitorStartResponse — treat crossRef as implicitly active.
          this.activeMonitors.add(facts.monitorCrossRefId)
        }
        break
      }
      default:
        break
    }
  }

  getFacts(): readonly CstaMonitorLifecycleFact[] {
    return this.facts
  }

  isMonitorActive(monitorCrossRefId: string): boolean {
    return this.activeMonitors.has(monitorCrossRefId)
  }

  pendingDeviceForInvoke(invokeId: string): string | null {
    return this.pendingStartByInvoke.get(invokeId)?.deviceId ?? null
  }
}

const CSTA_MONITOR_STORE = 'csta-monitor-graph'

export function cstaMonitorGraphForTransport(
  mapping: MappingLike,
  transportStoreKey: string,
): CstaMonitorSessionGraph {
  return protocolGraphEntry(mapping, `${CSTA_MONITOR_STORE}/${transportStoreKey}`, () => new CstaMonitorSessionGraph())
}

export function resetCstaMonitorGraphsForTests(): void {
  resetProtocolGraphStateRegistryForTests()
}
