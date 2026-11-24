import { describe, expect, it } from 'vitest'
import {
  compileColoringRules,
  createDefaultColoringRules,
  defaultColoringPresetFingerprint,
  evaluateColorSlots,
  evaluateFirstMatchSlot,
  meetsWcagAa,
  sanitizeColorPair,
  validateColorPair,
  correctForegroundForContrast,
  COLORING_LIMITS,
  NO_COLOR_SLOT,
} from '../../../src/pcap/coloring'
import { parseDisplayFilter, buildFilterContext, evaluateDisplayFilter } from '../../../src/pcap/displayFilter'
import type { PcapColoringRule } from '../../../src/pcap/coloring/types'

function sampleCtx(overrides: Partial<ReturnType<typeof buildFilterContext>> = {}) {
  return buildFilterContext({
    packetIndex: 0,
    packetNumber: 1,
    capturedLength: 100,
    linkType: 1,
    data: new Uint8Array(42),
    protocols: ['tcp'],
    changed: false,
    hasIssue: false,
    ...overrides,
  })
}

describe('pcap coloring', () => {
  it('default preset fingerprint is stable', () => {
    expect(defaultColoringPresetFingerprint()).toBe(defaultColoringPresetFingerprint())
    expect(createDefaultColoringRules().length).toBeGreaterThanOrEqual(10)
  })

  it('compiles default rules without errors', () => {
    const result = compileColoringRules(createDefaultColoringRules(), 1)
    expect(result.errors).toHaveLength(0)
    expect(result.rules.length).toBe(createDefaultColoringRules().length)
    expect(result.rules.every((r) => r.slot > NO_COLOR_SLOT)).toBe(true)
  })

  it('marks invalid filter rules with error and disables them', () => {
    const rules: PcapColoringRule[] = [
      {
        id: 'bad',
        name: 'Bad',
        enabled: true,
        priority: 1,
        filter: 'foo.bar == 1',
        light: { foreground: '#111111', background: '#f5f5f5' },
        dark: { foreground: '#f5f5f5', background: '#111111' },
        source: 'user',
      },
    ]
    const result = compileColoringRules(rules, 2)
    expect(result.errors.length).toBeGreaterThan(0)
    expect(result.rules[0]?.enabled).toBe(false)
    expect(result.rules[0]?.error).not.toBeNull()
  })

  it('evaluates first-match priority order', () => {
    const rules = compileColoringRules(
      [
        {
          id: 'tcp',
          name: 'TCP',
          enabled: true,
          priority: 50,
          filter: 'tcp',
          light: { foreground: '#111111', background: '#eeeeee' },
          dark: { foreground: '#eeeeee', background: '#111111' },
          source: 'user',
        },
        {
          id: 'issue',
          name: 'Issue',
          enabled: true,
          priority: 10,
          filter: 'frame.issue == true',
          light: { foreground: '#111111', background: '#ffeeee' },
          dark: { foreground: '#ffeeee', background: '#111111' },
          source: 'user',
        },
      ],
      3,
    )
    const ctxIssue = sampleCtx({ hasIssue: true, protocols: ['tcp'] })
    const issueSlot = evaluateFirstMatchSlot(rules.rules, ctxIssue)
    const issueRule = rules.rules.find((r) => r.id === 'issue')
    expect(issueSlot).toBe(issueRule?.slot)

    const ctxTcp = sampleCtx({ hasIssue: false, protocols: ['tcp'] })
    const tcpSlot = evaluateFirstMatchSlot(rules.rules, ctxTcp)
    const tcpRule = rules.rules.find((r) => r.id === 'tcp')
    expect(tcpSlot).toBe(tcpRule?.slot)
  })

  it('evaluateColorSlots fills Uint16Array per packet index', () => {
    const compiled = compileColoringRules(createDefaultColoringRules(), 4)
    const slots = evaluateColorSlots(compiled.rules, 3, (i) =>
      sampleCtx({ packetIndex: i, protocols: i === 1 ? ['sip'] : ['tcp'] }),
    )
    expect(slots).toBeInstanceOf(Uint16Array)
    expect(slots.length).toBe(3)
    expect(slots[1]).not.toBe(slots[0])
  })

  it('enforces persistent rule limit at compile time', () => {
    const tooMany: PcapColoringRule[] = Array.from({ length: COLORING_LIMITS.maxPersistentRules + 1 }, (_, i) => ({
      id: `r-${i}`,
      name: `R${i}`,
      enabled: true,
      priority: i,
      filter: 'tcp',
      light: { foreground: '#111111', background: '#f5f5f5' },
      dark: { foreground: '#f5f5f5', background: '#111111' },
      source: 'user' as const,
    }))
    const result = compileColoringRules(tooMany, 5)
    expect(result.rules).toHaveLength(0)
    expect(result.errors[0]?.message).toMatch(/64/)
  })

  it('validates sRGB and WCAG AA contrast', () => {
    const bad = validateColorPair({ foreground: '#cccccc', background: '#dddddd' })
    expect(bad).toBe('low-contrast')
    const fixed = sanitizeColorPair({ foreground: '#cccccc', background: '#dddddd' })
    expect(meetsWcagAa(fixed.foreground, fixed.background)).toBe(true)
    const corrected = correctForegroundForContrast('#cccccc', '#dddddd')
    expect(meetsWcagAa(corrected, '#dddddd')).toBe(true)
  })

  it('parser parity for default sip filter', () => {
    const expr = parseDisplayFilter('sip').expr
    const ctx = sampleCtx({ protocols: ['sip'] })
    expect(evaluateDisplayFilter(expr, ctx)).toBe(true)
  })
})
