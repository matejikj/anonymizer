/**
 * Single protocol catalog — analysis + kernel manifest share this list (no ALL_MODULES fork).
 */

import type { ProtocolModule as LegacyProtocolModule } from '../protocols/types'
import {
  LINKTYPE_ETHERNET, LINKTYPE_RAW_IPV4, LINKTYPE_RAW_IPV6, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2,
  LINKTYPE_NULL, LINKTYPE_LOOP,
  ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_ARP,
  IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IPV4, IPPROTO_IPV6, IPPROTO_GRE,
} from '../protocols/types'
import { ethernetModule } from '../protocols/link/ethernet'
import { sllModule, sll2Module } from '../protocols/link/sll'
import { rawIpv4Module, rawIpv6Module } from '../protocols/link/rawip'
import { nullLinkModule, loopLinkModule } from '../protocols/link/nullLoop'
import { arpModule } from '../protocols/network/arp'
import { ipv4Module } from '../protocols/network/ipv4'
import { ipv6Module } from '../protocols/network/ipv6'
import { ipInIpModule, ipv6InIpModule, greModule } from '../protocols/network/tunnel'
import { vxlanModule, VXLAN_UDP_PORT } from '../protocols/network/vxlan'
import { tcpModule } from '../protocols/transport/tcp'
import { udpModule } from '../protocols/transport/udp'
import { sctpModule } from '../protocols/transport/sctp'
import { icmpv4Module, icmpv6Module } from '../protocols/transport/icmp'
import { ProtocolManifest } from './manifest'
import { wrapLegacyProtocolModule } from './adapters/legacyProtocolAdapter'
import type { DispatchSelector, ProtocolLayer } from './types'
import { echoUdpExampleModule } from './onboarding/echoUdpExample'
import { rndDispatchLiteModule } from './onboarding/rndDispatchLiteModule'

interface CatalogRow {
  readonly legacy: LegacyProtocolModule
  readonly layer: ProtocolLayer
  readonly selectors: readonly DispatchSelector[]
  readonly title: string
  readonly priority?: number
}

const CATALOG_ROWS: readonly CatalogRow[] = [
  {
    legacy: nullLinkModule,
    layer: 'link',
    selectors: [{ kind: 'linktype', value: LINKTYPE_NULL }],
    title: 'NULL (BSD/macOS loopback)',
    priority: 200,
  },
  {
    legacy: loopLinkModule,
    layer: 'link',
    selectors: [{ kind: 'linktype', value: LINKTYPE_LOOP }],
    title: 'LOOP (OpenBSD)',
    priority: 200,
  },
  {
    legacy: ethernetModule,
    layer: 'link',
    selectors: [{ kind: 'linktype', value: LINKTYPE_ETHERNET }],
    title: 'Ethernet',
    priority: 200,
  },
  {
    legacy: sllModule,
    layer: 'link',
    selectors: [{ kind: 'linktype', value: LINKTYPE_LINUX_SLL }],
    title: 'Linux SLL',
  },
  {
    legacy: sll2Module,
    layer: 'link',
    selectors: [{ kind: 'linktype', value: LINKTYPE_LINUX_SLL2 }],
    title: 'Linux SLL2',
  },
  {
    legacy: rawIpv4Module,
    layer: 'link',
    selectors: [{ kind: 'linktype', value: LINKTYPE_RAW_IPV4 }],
    title: 'Raw IPv4',
  },
  {
    legacy: rawIpv6Module,
    layer: 'link',
    selectors: [{ kind: 'linktype', value: LINKTYPE_RAW_IPV6 }],
    title: 'Raw IPv6',
  },
  {
    legacy: arpModule,
    layer: 'network',
    selectors: [{ kind: 'ethertype', value: ETHERTYPE_ARP }],
    title: 'ARP',
  },
  {
    legacy: ipv4Module,
    layer: 'network',
    selectors: [{ kind: 'ethertype', value: ETHERTYPE_IPV4 }],
    title: 'IPv4',
    priority: 180,
  },
  {
    legacy: ipv6Module,
    layer: 'network',
    selectors: [{ kind: 'ethertype', value: ETHERTYPE_IPV6 }],
    title: 'IPv6',
    priority: 180,
  },
  {
    legacy: ipInIpModule,
    layer: 'tunnel',
    selectors: [{ kind: 'ip-protocol', value: IPPROTO_IPV4 }],
    title: 'IP-in-IP',
  },
  {
    legacy: ipv6InIpModule,
    layer: 'tunnel',
    selectors: [{ kind: 'ip-protocol', value: IPPROTO_IPV6 }],
    title: 'IPv6-in-IP',
  },
  {
    legacy: greModule,
    layer: 'tunnel',
    selectors: [{ kind: 'ip-protocol', value: IPPROTO_GRE }],
    title: 'GRE',
  },
  {
    legacy: vxlanModule,
    layer: 'tunnel',
    selectors: [{ kind: 'udp-port', value: VXLAN_UDP_PORT }],
    title: 'VXLAN',
  },
  {
    legacy: tcpModule,
    layer: 'transport',
    selectors: [{ kind: 'ip-protocol', value: IPPROTO_TCP }],
    title: 'TCP',
    priority: 160,
  },
  {
    legacy: udpModule,
    layer: 'transport',
    selectors: [{ kind: 'ip-protocol', value: IPPROTO_UDP }],
    title: 'UDP',
    priority: 160,
  },
  {
    legacy: sctpModule,
    layer: 'transport',
    selectors: [{ kind: 'ip-protocol', value: IPPROTO_SCTP }],
    title: 'SCTP',
    priority: 160,
  },
  {
    legacy: icmpv4Module,
    layer: 'transport',
    selectors: [{ kind: 'ip-protocol', value: IPPROTO_ICMP }],
    title: 'ICMPv4',
  },
  {
    legacy: icmpv6Module,
    layer: 'transport',
    selectors: [{ kind: 'ip-protocol', value: IPPROTO_ICMPV6 }],
    title: 'ICMPv6',
  },
]

let sharedManifest: ProtocolManifest | null = null

/** Shared manifest singleton — compiled once per worker/realm. */
export function getSharedProtocolManifest(): ProtocolManifest {
  if (sharedManifest) return sharedManifest
  const manifest = new ProtocolManifest()
  for (const row of CATALOG_ROWS) {
    manifest.register(
      wrapLegacyProtocolModule({
        legacy: row.legacy,
        layer: row.layer,
        selectors: row.selectors,
        title: row.title,
        priority: row.priority,
      }),
      row.legacy,
    )
  }
  // T-01.6 onboarding example — proves module+manifest+corpus without central switch edits.
  manifest.register(echoUdpExampleModule)
  // T31 — descriptor-compiled proprietary pilot (synthetic RND Dispatch Lite).
  manifest.register(rndDispatchLiteModule)
  sharedManifest = manifest
  return manifest
}

/** Legacy ProtocolModule list for analysis.collect — derived from the manifest, not a fork. */
export function catalogLegacyModules(): readonly LegacyProtocolModule[] {
  return getSharedProtocolManifest().legacyModules()
}

/** Test helper — reset singleton between isolated suite runs. */
export function resetSharedProtocolManifestForTests(): void {
  sharedManifest = null
}

/** T32 — catalog rows for support matrix (id/title/layer/selectors). */
export function listCatalogProtocols(): readonly {
  readonly id: string
  readonly title: string
  readonly layer: ProtocolLayer
  readonly selectors: readonly DispatchSelector[]
}[] {
  return CATALOG_ROWS.map((row) => ({
    id: row.legacy.id,
    title: row.title,
    layer: row.layer,
    selectors: row.selectors,
  }))
}
