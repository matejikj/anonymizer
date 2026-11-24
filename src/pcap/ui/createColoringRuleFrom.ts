/**
 * Build supported "Create coloring rule from…" filter expressions.
 */

import type { PacketFilterContext } from '../displayFilter'
import { conversationIdFromFilterContext } from '../coloring/conversation'
import { highestProtocol } from './packetListRowModel'

export type CreateColoringRuleKind = 'protocol' | 'ip.src' | 'ip.dst' | 'tcp.port' | 'udp.port' | 'conversation'

export interface CreateColoringRuleDraft {
  readonly kind: CreateColoringRuleKind
  readonly name: string
  readonly filter: string
}

export function buildCreateColoringRuleOptions(
  ctx: PacketFilterContext,
  protocols: readonly string[],
): readonly CreateColoringRuleDraft[] {
  const out: CreateColoringRuleDraft[] = []
  const proto = highestProtocol(protocols)
  if (proto && proto !== '—') {
    const filterProto = proto.toLowerCase().replace(/\s+/g, '')
    // Use first protocol token that display filter understands when possible.
    const token =
      protocols.find((p) => ['sip', 'sdp', 'dns', 'tcp', 'udp', 'rtp', 'rtcp', 'arp', 'ipv4', 'ipv6'].includes(p.toLowerCase())) ??
      filterProto
    if (['sip', 'sdp', 'dns', 'mdns', 'tcp', 'udp', 'rtp', 'rtcp', 'arp', 'ipv4', 'ipv6', 'icmp', 'icmpv4', 'icmpv6'].includes(token.toLowerCase())) {
      out.push({
        kind: 'protocol',
        name: `Protocol ${token}`,
        filter: token.toLowerCase() === 'mdns' ? 'mdns' : token.toLowerCase(),
      })
    }
  }
  if (ctx.srcIpv4) {
    out.push({ kind: 'ip.src', name: `ip.src == ${ctx.srcIpv4}`, filter: `ip.src == ${ctx.srcIpv4}` })
  }
  if (ctx.dstIpv4) {
    out.push({ kind: 'ip.dst', name: `ip.dst == ${ctx.dstIpv4}`, filter: `ip.dst == ${ctx.dstIpv4}` })
  }
  if (ctx.l4Proto === 'tcp' && ctx.srcPort !== undefined) {
    out.push({
      kind: 'tcp.port',
      name: `tcp.port == ${ctx.srcPort}`,
      filter: `tcp.port == ${ctx.srcPort}`,
    })
  }
  if (ctx.l4Proto === 'udp' && ctx.srcPort !== undefined) {
    out.push({
      kind: 'udp.port',
      name: `udp.port == ${ctx.srcPort}`,
      filter: `udp.port == ${ctx.srcPort}`,
    })
  }
  const conv = conversationIdFromFilterContext(ctx)
  if (conv && ctx.srcIpv4) {
    out.push({
      kind: 'conversation',
      name: 'Conversation',
      filter: `ip.addr == ${ctx.srcIpv4}`,
    })
  }
  return out
}
