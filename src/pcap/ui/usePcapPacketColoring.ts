/**
 * Sync packet coloring evaluation + CSS palette application.
 * Chunked main-thread evaluation (Worker-ready Uint16Array tables).
 */

import { useEffect, useMemo, useRef } from 'react'
import {
  buildColorPalette,
  compileColoringRules,
  evaluateColorSlotsChunked,
  findRuleBySlot,
  type CompiledColoringRule,
} from '../coloring'
import { buildFilterContextFromSession, getPacketCount } from './pcapSession'
import { usePcapStore } from './pcapStore'

export interface PcapColoringState {
  readonly compiled: readonly CompiledColoringRule[]
  readonly slotsOriginal: Uint16Array
  readonly slotsAnonymized: Uint16Array
  readonly revision: number
}

function emptySlots(): Uint16Array {
  return new Uint16Array(0)
}

export function usePcapPacketColoring(sessionEpoch: number): PcapColoringState {
  const coloringRules = usePcapStore((s) => s.coloringRules)
  const coloringRulesRevision = usePcapStore((s) => s.coloringRulesRevision)
  const setColorSlots = usePcapStore((s) => s.setColorSlots)
  const cancelRef = useRef(0)

  const compiled = useMemo(
    () => compileColoringRules(coloringRules, coloringRulesRevision),
    [coloringRules, coloringRulesRevision],
  )

  useEffect(() => {
    const gen = ++cancelRef.current
    if (sessionEpoch < 0) {
      setColorSlots(emptySlots(), emptySlots(), compiled.revision)
      return
    }
    const count = getPacketCount()
    if (count === 0) {
      setColorSlots(emptySlots(), emptySlots(), compiled.revision)
      return
    }

    let cancelled = false
    const run = async () => {
      const original = await evaluateColorSlotsChunked(
        compiled.rules,
        count,
        (i) => buildFilterContextFromSession(i, 'original'),
        { chunkSize: 256, isCancelled: () => cancelled || cancelRef.current !== gen },
      )
      if (cancelled || cancelRef.current !== gen) return
      const anonymized = await evaluateColorSlotsChunked(
        compiled.rules,
        count,
        (i) => buildFilterContextFromSession(i, 'anonymized'),
        { chunkSize: 256, isCancelled: () => cancelled || cancelRef.current !== gen },
      )
      if (cancelled || cancelRef.current !== gen) return
      // Atomic publish after both views finish the same revision.
      setColorSlots(original, anonymized, compiled.revision)
    }
    void run()
    return () => {
      cancelled = true
    }
  }, [sessionEpoch, compiled, setColorSlots])

  const colorSlotsOriginal = usePcapStore((s) => s.colorSlotsOriginal)
  const colorSlotsAnonymized = usePcapStore((s) => s.colorSlotsAnonymized)
  const colorSlotsRevision = usePcapStore((s) => s.colorSlotsRevision)

  return {
    compiled: compiled.rules,
    slotsOriginal: colorSlotsOriginal,
    slotsAnonymized: colorSlotsAnonymized,
    revision: colorSlotsRevision,
  }
}

export function applyColorPaletteToElement(
  el: HTMLElement,
  compiled: readonly CompiledColoringRule[],
): void {
  const palette = buildColorPalette(compiled)
  for (const [slot, colors] of palette) {
    el.style.setProperty(`--pcap-color-slot-${slot}-fg-light`, colors.light.foreground)
    el.style.setProperty(`--pcap-color-slot-${slot}-bg-light`, colors.light.background)
    el.style.setProperty(`--pcap-color-slot-${slot}-fg-dark`, colors.dark.foreground)
    el.style.setProperty(`--pcap-color-slot-${slot}-bg-dark`, colors.dark.background)
  }

  const styleId = 'pcap-color-slot-rules'
  let styleEl = el.querySelector<HTMLStyleElement>(`#${styleId}`)
  if (!styleEl) {
    styleEl = document.createElement('style')
    styleEl.id = styleId
    el.appendChild(styleEl)
  }
  const rules = [...palette.keys()]
    .map(
      (slot) => `
.pcap-tables .pcap-row[data-color-slot="${slot}"] {
  --pcap-color-rule-fg: var(--pcap-color-slot-${slot}-fg-light);
  --pcap-color-rule-bg: var(--pcap-color-slot-${slot}-bg-light);
}
[data-theme='dark'] .pcap-tables .pcap-row[data-color-slot="${slot}"] {
  --pcap-color-rule-fg: var(--pcap-color-slot-${slot}-fg-dark);
  --pcap-color-rule-bg: var(--pcap-color-slot-${slot}-bg-dark);
}
@media (forced-colors: active) {
  .pcap-tables .pcap-row[data-color-slot="${slot}"] {
    --pcap-color-rule-bg: transparent;
  }
}`,
    )
    .join('\n')
  styleEl.textContent = rules
}

export function selectedPacketColorRuleName(
  compiled: readonly CompiledColoringRule[],
  slot: number,
): string | null {
  const rule = findRuleBySlot(compiled, slot)
  return rule?.name ?? null
}
