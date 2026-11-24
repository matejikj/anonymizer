/**
 * Stable conversation ID for temporary coloring (TCP → UDP → IP → Ethernet).
 */

import { conversationKeyFromEndpoint } from '../reassembly/flowKey'
import type { PacketFilterContext } from '../displayFilter'

export function conversationIdFromFilterContext(ctx: PacketFilterContext): string | null {
  if (ctx.l4Proto === 'tcp' && ctx.srcIpv4 && ctx.dstIpv4 && ctx.srcPort !== undefined && ctx.dstPort !== undefined) {
    return conversationKeyFromEndpoint({
      srcIp: ctx.srcIpv4,
      dstIp: ctx.dstIpv4,
      srcPort: ctx.srcPort,
      dstPort: ctx.dstPort,
      ipProto: 6,
    })
  }
  if (ctx.l4Proto === 'udp' && ctx.srcIpv4 && ctx.dstIpv4 && ctx.srcPort !== undefined && ctx.dstPort !== undefined) {
    return conversationKeyFromEndpoint({
      srcIp: ctx.srcIpv4,
      dstIp: ctx.dstIpv4,
      srcPort: ctx.srcPort,
      dstPort: ctx.dstPort,
      ipProto: 17,
    })
  }
  if (ctx.srcIpv4 && ctx.dstIpv4) {
    const a = ctx.srcIpv4
    const b = ctx.dstIpv4
    const [left, right] = a <= b ? [a, b] : [b, a]
    return `ip:${left}<->${right}`
  }
  if (ctx.srcMac && ctx.dstMac) {
    const a = ctx.srcMac.toLowerCase()
    const b = ctx.dstMac.toLowerCase()
    const [left, right] = a <= b ? [a, b] : [b, a]
    return `eth:${left}<->${right}`
  }
  return null
}

/** Ten distinct conversation palette presets (session-only). */
export const CONVERSATION_PALETTE: readonly { light: { foreground: string; background: string }; dark: { foreground: string; background: string } }[] = [
  { light: { foreground: '#1e3a5f', background: '#dbeafe' }, dark: { foreground: '#bfdbfe', background: '#1e3a5f' } },
  { light: { foreground: '#14532d', background: '#dcfce7' }, dark: { foreground: '#86efac', background: '#14532d' } },
  { light: { foreground: '#713f12', background: '#fef3c7' }, dark: { foreground: '#fcd34d', background: '#713f12' } },
  { light: { foreground: '#581c87', background: '#f3e8ff' }, dark: { foreground: '#d8b4fe', background: '#581c87' } },
  { light: { foreground: '#831843', background: '#fce7f3' }, dark: { foreground: '#f9a8d4', background: '#831843' } },
  { light: { foreground: '#134e4a', background: '#ccfbf1' }, dark: { foreground: '#5eead4', background: '#134e4a' } },
  { light: { foreground: '#7c2d12', background: '#ffedd5' }, dark: { foreground: '#fdba74', background: '#7c2d12' } },
  { light: { foreground: '#312e81', background: '#e0e7ff' }, dark: { foreground: '#a5b4fc', background: '#312e81' } },
  { light: { foreground: '#365314', background: '#ecfccb' }, dark: { foreground: '#bef264', background: '#365314' } },
  { light: { foreground: '#1f2937', background: '#f3f4f6' }, dark: { foreground: '#e5e7eb', background: '#1f2937' } },
]
