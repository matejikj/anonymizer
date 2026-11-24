/**
 * First-match coloring evaluation — chunked main-thread; Worker-ready Uint16Array tables.
 */

import type { PacketFilterContext } from '../displayFilter'
import { evaluateDisplayFilter } from '../displayFilter'
import type { CompiledColoringRule } from './types'
import { NO_COLOR_SLOT } from './types'

export function evaluateFirstMatchSlot(
  rules: readonly CompiledColoringRule[],
  ctx: PacketFilterContext,
): number {
  for (const rule of rules) {
    if (!rule.enabled || rule.error || !rule.expr) continue
    if (evaluateDisplayFilter(rule.expr, ctx)) return rule.slot
  }
  return NO_COLOR_SLOT
}

export function evaluateColorSlots(
  rules: readonly CompiledColoringRule[],
  packetCount: number,
  buildContext: (packetIndex: number) => PacketFilterContext | null,
): Uint16Array {
  const slots = new Uint16Array(packetCount)
  for (let i = 0; i < packetCount; i++) {
    const ctx = buildContext(i)
    slots[i] = ctx ? evaluateFirstMatchSlot(rules, ctx) : NO_COLOR_SLOT
  }
  return slots
}

export async function evaluateColorSlotsChunked(
  rules: readonly CompiledColoringRule[],
  packetCount: number,
  buildContext: (packetIndex: number) => PacketFilterContext | null,
  opts: { readonly chunkSize?: number; readonly isCancelled?: () => boolean } = {},
): Promise<Uint16Array> {
  const chunkSize = opts.chunkSize ?? 256
  const slots = new Uint16Array(packetCount)
  for (let start = 0; start < packetCount; start += chunkSize) {
    if (opts.isCancelled?.()) break
    const end = Math.min(packetCount, start + chunkSize)
    for (let i = start; i < end; i++) {
      const ctx = buildContext(i)
      slots[i] = ctx ? evaluateFirstMatchSlot(rules, ctx) : NO_COLOR_SLOT
    }
    if (end < packetCount) {
      await new Promise<void>((resolve) => {
        if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => resolve())
        else setTimeout(resolve, 0)
      })
    }
  }
  return slots
}

export function findRuleBySlot(
  rules: readonly CompiledColoringRule[],
  slot: number,
): CompiledColoringRule | undefined {
  if (slot === NO_COLOR_SLOT) return undefined
  return rules.find((r) => r.slot === slot)
}
