/**
 * Single static protocol manifest — replaces dual ALL_MODULES / sanitize dispatch lists.
 * Dispatch indexes are compiled once at worker start.
 */

import type { ProtocolModule as LegacyProtocolModule } from '../protocols/types'
import type { KernelProtocolModule } from './protocolModule'
import type { DispatchSelector, ProtocolDescriptor, ProtocolLayer } from './types'
import { PCAP_KERNEL_BUDGETS } from '../../domain/capabilityContract'

export interface ManifestEntry {
  readonly module: KernelProtocolModule
  readonly legacy?: LegacyProtocolModule
}

export interface CompiledDispatchIndex {
  readonly byLinkType: ReadonlyMap<number, readonly ManifestEntry[]>
  readonly byEtherType: ReadonlyMap<number, readonly ManifestEntry[]>
  readonly byIpProtocol: ReadonlyMap<number, readonly ManifestEntry[]>
  readonly byUdpPort: ReadonlyMap<number, readonly ManifestEntry[]>
  readonly byTcpPort: ReadonlyMap<number, readonly ManifestEntry[]>
  readonly byId: ReadonlyMap<string, ManifestEntry>
  readonly all: readonly ManifestEntry[]
  readonly maxProbesPerUnit: number
  readonly maxProbeBytes: number
  readonly maxProbeNesting: number
}

export class ProtocolManifest {
  private readonly entries: ManifestEntry[] = []
  private compiled: CompiledDispatchIndex | null = null

  register(module: KernelProtocolModule, legacy?: LegacyProtocolModule): void {
    if (this.entries.some((e) => e.module.descriptor.id === module.descriptor.id)) {
      throw new Error(`Duplicate protocol manifest id: ${module.descriptor.id}`)
    }
    this.entries.push({ module, legacy })
    this.compiled = null
  }

  /** Legacy analysis modules — single source; analysis.ts must not keep a parallel list. */
  legacyModules(): readonly LegacyProtocolModule[] {
    return this.entries.map((e) => e.legacy).filter((m): m is LegacyProtocolModule => m !== undefined)
  }

  descriptors(): readonly ProtocolDescriptor[] {
    return this.entries.map((e) => e.module.descriptor)
  }

  compile(): CompiledDispatchIndex {
    if (this.compiled) return this.compiled
    const byLinkType = new Map<number, ManifestEntry[]>()
    const byEtherType = new Map<number, ManifestEntry[]>()
    const byIpProtocol = new Map<number, ManifestEntry[]>()
    const byUdpPort = new Map<number, ManifestEntry[]>()
    const byTcpPort = new Map<number, ManifestEntry[]>()
    const byId = new Map<string, ManifestEntry>()

    const sorted = [...this.entries].sort(
      (a, b) => b.module.descriptor.priority - a.module.descriptor.priority,
    )

    for (const entry of sorted) {
      byId.set(entry.module.descriptor.id, entry)
      for (const sel of entry.module.descriptor.selectors) {
        pushSelector(sel, entry, {
          byLinkType,
          byEtherType,
          byIpProtocol,
          byUdpPort,
          byTcpPort,
        })
      }
    }

    this.compiled = {
      byLinkType,
      byEtherType,
      byIpProtocol,
      byUdpPort,
      byTcpPort,
      byId,
      all: sorted,
      maxProbesPerUnit: PCAP_KERNEL_BUDGETS.maxProbesPerUnit,
      maxProbeBytes: PCAP_KERNEL_BUDGETS.maxProbeBytes,
      maxProbeNesting: PCAP_KERNEL_BUDGETS.maxProbeNesting,
    }
    return this.compiled
  }
}

function pushSelector(
  sel: DispatchSelector,
  entry: ManifestEntry,
  maps: {
    byLinkType: Map<number, ManifestEntry[]>
    byEtherType: Map<number, ManifestEntry[]>
    byIpProtocol: Map<number, ManifestEntry[]>
    byUdpPort: Map<number, ManifestEntry[]>
    byTcpPort: Map<number, ManifestEntry[]>
  },
): void {
  const push = (map: Map<number, ManifestEntry[]>, key: number) => {
    const list = map.get(key)
    if (list) list.push(entry)
    else map.set(key, [entry])
  }
  switch (sel.kind) {
    case 'linktype':
      push(maps.byLinkType, sel.value)
      break
    case 'ethertype':
      push(maps.byEtherType, sel.value)
      break
    case 'ip-protocol':
      push(maps.byIpProtocol, sel.value)
      break
    case 'udp-port':
      push(maps.byUdpPort, sel.value)
      break
    case 'tcp-port':
      push(maps.byTcpPort, sel.value)
      break
    case 'content-type':
    case 'ppid':
      // Content / PPID selectors are probed from a bounded candidate list at analyze time.
      break
    default: {
      const _exhaustive: never = sel
      void _exhaustive
    }
  }
}

export function defaultDescriptor(input: {
  id: string
  layer: ProtocolLayer
  selectors: readonly DispatchSelector[]
  priority?: number
  title: string
  specRefs?: readonly string[]
}): ProtocolDescriptor {
  return {
    id: input.id,
    layer: input.layer,
    selectors: input.selectors,
    priority: input.priority ?? 100,
    capabilities: {
      structured: true,
      secretsMasked: true,
      supportsTcpReassembly: input.layer === 'application',
      supportsUdpDatagram: true,
    },
    resourceLimits: {
      maxMessageBytes: 256 * 1024,
      maxFields: 4_096,
      maxNesting: 4,
    },
    documentation: {
      title: input.title,
      specRefs: input.specRefs ?? [],
      supportProfile: 'structured',
    },
  }
}
