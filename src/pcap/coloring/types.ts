/**
 * Wireshark-like packet list coloring rules (step 2 side-by-side).
 */

import type { FilterExpr } from '../displayFilter'

export type ColoringRuleSource = 'default' | 'user' | 'temporary-conversation'

export interface PcapColorPair {
  readonly foreground: string
  readonly background: string
}

export interface PcapColoringRule {
  readonly id: string
  readonly name: string
  readonly enabled: boolean
  readonly priority: number
  readonly filter: string
  readonly light: PcapColorPair
  readonly dark: PcapColorPair
  readonly source: ColoringRuleSource
}

export interface CompiledColoringRule {
  readonly id: string
  readonly name: string
  readonly enabled: boolean
  readonly priority: number
  readonly filter: string
  readonly expr: FilterExpr | null
  readonly slot: number
  readonly light: PcapColorPair
  readonly dark: PcapColorPair
  readonly source: ColoringRuleSource
  readonly error: { readonly message: string; readonly offset: number } | null
}

export interface CompileColoringRulesResult {
  readonly rules: readonly CompiledColoringRule[]
  readonly revision: number
  readonly errors: readonly { readonly ruleId: string; readonly message: string; readonly offset: number }[]
}

export interface ColorPaletteSlot {
  readonly slot: number
  readonly light: PcapColorPair
  readonly dark: PcapColorPair
}

export const COLORING_LIMITS = {
  maxPersistentRules: 64,
  maxTemporarySlots: 10,
  maxFilterBytes: 4096,
  maxNameLength: 128,
  maxPaletteSlots: 74,
} as const

/** Slot 0 — no coloring rule matched. */
export const NO_COLOR_SLOT = 0

/** First slot reserved for temporary conversation colors. */
export const TEMP_CONVERSATION_SLOT_BASE = 64

export const DEFAULT_COLORING_PRESET_VERSION = 1
