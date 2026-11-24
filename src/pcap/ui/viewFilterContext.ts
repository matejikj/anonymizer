/**
 * Build display-filter / coloring contexts for Original vs Anonymized views.
 */

import type { EntityCategory } from '../anonymization/entityRegistry'
import { aliasFromSnapshot } from '../mapping/pcapMappingPort'
import { getSharedMappingClient } from '../../mapping/sharedMappingClient'
import type { MappingSnapshot } from '../../mapping/types'
import type { PacketFilterContext } from '../displayFilter'

export function mapEntityValueForView(
  category: string,
  value: string,
  dataView: 'original' | 'anonymized',
  snapshot: MappingSnapshot | null = getSharedMappingClient().getPublishedSnapshot(),
): string {
  if (dataView !== 'anonymized' || !snapshot) return value
  if (category === 'port') {
    // Ports may be stored as "tcp/5060" — map numeric part when remapped.
    const slash = value.indexOf('/')
    if (slash > 0) {
      const proto = value.slice(0, slash)
      const num = value.slice(slash + 1)
      const alias = aliasFromSnapshot(snapshot, 'port' as EntityCategory, num)
      return alias ? `${proto}/${alias}` : value
    }
  }
  const alias = aliasFromSnapshot(snapshot, category as EntityCategory, value)
  return alias ?? value
}

export function mapEndpointValues(
  values: readonly string[],
  category: string,
  dataView: 'original' | 'anonymized',
): string[] {
  return values.map((v) => mapEntityValueForView(category, v, dataView))
}

export function withViewMappedEndpoints(
  ctx: PacketFilterContext,
  dataView: 'original' | 'anonymized',
  snapshot: MappingSnapshot | null = getSharedMappingClient().getPublishedSnapshot(),
): PacketFilterContext {
  if (dataView !== 'anonymized' || !snapshot) return ctx
  return {
    ...ctx,
    srcIpv4: ctx.srcIpv4 ? mapEntityValueForView('ipv4', ctx.srcIpv4, dataView, snapshot) : undefined,
    dstIpv4: ctx.dstIpv4 ? mapEntityValueForView('ipv4', ctx.dstIpv4, dataView, snapshot) : undefined,
    srcMac: ctx.srcMac ? mapEntityValueForView('mac', ctx.srcMac, dataView, snapshot) : undefined,
    dstMac: ctx.dstMac ? mapEntityValueForView('mac', ctx.dstMac, dataView, snapshot) : undefined,
    srcPort: mapPortNumber(ctx.srcPort, snapshot),
    dstPort: mapPortNumber(ctx.dstPort, snapshot),
  }
}

function mapPortNumber(port: number | undefined, snapshot: MappingSnapshot): number | undefined {
  if (port === undefined) return undefined
  const alias = aliasFromSnapshot(snapshot, 'port', String(port))
  if (!alias) return port
  const n = Number.parseInt(alias, 10)
  return Number.isFinite(n) ? n : port
}
