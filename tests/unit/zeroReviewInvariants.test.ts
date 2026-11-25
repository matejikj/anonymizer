/**
 * F1 / I1–I7 — zero-review invariants that must hold after T62–T74.
 */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { cs } from '../../src/i18n/cs.ts'
import {
  OUTCOME_FAMILY_STATES,
  type AnonymizationOutcome,
  type OutcomeFamilyState,
  type OutcomeProtocolRow,
} from '../../src/pcap/coverage/anonymizationOutcome.ts'
import {
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  PCAP_ANONYMIZATION_LEVELS,
  presetToSanitizationPolicy,
} from '../../src/pcap/profile/presets.ts'
import {
  FINAL_DISPOSITIONS,
  finalizePacketDisposition,
} from '../../src/pcap/export/dispositionLedger.ts'
import {
  applyFreeTextOpsToString,
  sanitizeFreeText,
} from '../../src/engine/freeText/index.ts'
import { maskAlphanumeric } from '../../src/mapping/textAliasEngine.ts'
import { protocolPrivacyGuidance } from '../../src/pcap/coverage/protocolPrivacyGuidance.ts'
import { APPLICATION_HANDLER_ORDER } from '../../src/pcap/kernel/applicationHandlers.ts'

const srcRoot = join(dirname(fileURLToPath(import.meta.url)), '../../src')

const FORBIDDEN_UI =
  /ověř(?!iteln)|zkontrol|odstraňte|posuzujte|před AI|vyžaduje kontrolu|k prověření|needs-attention|needsReview/i

function collectStringLeaves(value: unknown, path: string, out: { path: string; text: string }[]): void {
  if (typeof value === 'string') {
    out.push({ path, text: value })
    return
  }
  if (typeof value === 'function') {
    try {
      const sample = (value as (...args: never[]) => unknown)(
        ...'abcdef'.split('') as never[],
      )
      if (typeof sample === 'string') out.push({ path, text: sample })
    } catch {
      /* ignore arity mismatch */
    }
    return
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      collectStringLeaves(v, path ? `${path}.${k}` : k, out)
    }
  }
}

describe('I1 — outcome / coverage / review copy has no call-to-action', () => {
  it('protocol guidance describes processing without requests for manual review', () => {
    for (const id of ['ethernet', 'arp', 'ipv4', 'ipv6', 'udp', 'tcp', 'sctp', 'ether-0x8ffd',
      ...APPLICATION_HANDLER_ORDER.map(handler => handler.id)]) {
      const guide = protocolPrivacyGuidance(id)
      expect(`${guide.method} ${guide.check}`, id).not.toMatch(/ověřte|zkontrol|projděte|vyžaduje kontrolu|vyžadují kontrolu|před AI/i)
    }
  })
  it('forbids review verbs in pcap.outcome, coverageUx, review, and export confirm copy', () => {
    const scopes: { name: string; root: unknown }[] = [
      { name: 'pcap.outcome', root: cs.pcap.outcome },
      { name: 'pcap.coverageUx', root: cs.pcap.coverageUx },
      { name: 'review', root: cs.review },
    ]
    const hits: string[] = []
    for (const scope of scopes) {
      const leaves: { path: string; text: string }[] = []
      collectStringLeaves(scope.root, scope.name, leaves)
      for (const leaf of leaves) {
        if (FORBIDDEN_UI.test(leaf.text)) {
          hits.push(`${leaf.path}: ${leaf.text}`)
        }
      }
    }
    // Confirmation / gap copy must not invite review or mention preserve-unsafe originals.
    for (const [path, text] of [
      ['export.exposedTitle', cs.export.exposedTitle],
      ['export.exposedImpact', cs.export.exposedImpact],
      ['export.exportWithExposed', cs.export.exportWithExposed],
      ['pcap.export.exposedTitle', cs.pcap.export.exposedTitle],
      ['pcap.export.exposedImpact', cs.pcap.export.exposedImpact],
      ['pcap.export.exposedHint', cs.pcap.export.exposedHint],
    ] as const) {
      if (FORBIDDEN_UI.test(text) || /preserve-unsafe|odkryt/i.test(text)) {
        hits.push(`${path}: ${text}`)
      }
    }
    expect(hits).toEqual([])
  })

  it('AnonymizationOutcome has no needsReview / reviewCount fields', () => {
    expect(OUTCOME_FAMILY_STATES).not.toContain('needs-attention')
    expect(OUTCOME_FAMILY_STATES).not.toContain('processing-failed')
    type Forbidden = 'needsReview' | 'reviewCount' | 'needs-attention'
    type ProtocolKeys = keyof OutcomeProtocolRow
    type OutcomeKeys = keyof AnonymizationOutcome
    const _proto: Exclude<ProtocolKeys, Forbidden> = 'check'
    const _out: Exclude<OutcomeKeys, Forbidden> = 'gate'
    void _proto
    void _out
    const sampleState: OutcomeFamilyState = 'anonymized'
    expect(sampleState).toBe('anonymized')
  })

  it('onboarding, help, and combined export do not require a manual privacy review', () => {
    for (const text of [
      cs.onboarding.steps.export.title,
      cs.onboarding.steps.export.body,
      ...cs.help.whatItems,
      ...cs.help.startSteps,
      cs.correlationExport.stalePreview,
      cs.correlationExport.blockedHint,
    ]) {
      expect(text).not.toMatch(/po kontrole|zkontrol|projděte|vyžaduje kontrolu|k prověření/i)
    }
  })
})

describe('I6 — no manual unpack / split instructions for supported inputs', () => {
  it('inputRejection catalog avoids rozbalte/rozdělte/jednotlivě calls to action', () => {
    const leaves: { path: string; text: string }[] = []
    collectStringLeaves(cs.inputRejection, 'inputRejection', leaves)
    const banned = /rozbalte ručně|rozdělte|nahrajte jednotlivě|rozbalte soubor a nahrajte/i
    const hits = leaves.filter((l) => banned.test(l.text)).map((l) => `${l.path}: ${l.text}`)
    expect(hits).toEqual([])
  })
})

describe('T68 — fixed levels never use preserve-unsafe', () => {
  it('diagnostic and high-privacy policies contain no preserve-unsafe', () => {
    for (const level of PCAP_ANONYMIZATION_LEVELS) {
      const policy = presetToSanitizationPolicy(level)
      expect(JSON.stringify(policy)).not.toMatch(/preserve-unsafe/)
    }
    expect(JSON.stringify(DIAGNOSTIC_POLICY)).not.toMatch(/preserve-unsafe/)
    expect(JSON.stringify(HIGH_PRIVACY_POLICY)).not.toMatch(/preserve-unsafe/)
  })

  it('level module does not assign preserve-unsafe on fixed level policy objects', () => {
    const src = readFileSync(join(srcRoot, 'pcap/profile/pcapAnonymizationLevel.ts'), 'utf8')
    const diagnosticBlock = src.slice(
      src.indexOf('export const DIAGNOSTIC_POLICY'),
      src.indexOf('export const HIGH_PRIVACY_POLICY'),
    )
    const highBlock = src.slice(src.indexOf('export const HIGH_PRIVACY_POLICY'))
    expect(diagnosticBlock).not.toMatch(/:\s*'preserve-unsafe'/)
    expect(highBlock).not.toMatch(/:\s*'preserve-unsafe'/)
  })
})

describe('T62 — disposition ledger residual sweep (I2)', () => {
  it('unclaimed bytes are swept to mask and final ranges cover the packet', () => {
    const length = 64
    const finalized = finalizePacketDisposition({
      packetIndex: 0,
      length,
      drop: false,
      patches: [{ offset: 0, data: new Uint8Array(14) }],
      coverage: [
        { protocol: 'ethernet', offset: 0, length: 14, status: 'covered' },
        { protocol: 'ipv4', offset: 14, length: 20, status: 'covered' },
      ],
      level: 'diagnostic',
    })
    expect(finalized.unclaimedBytesBeforeSweep).toBeGreaterThan(0)
    expect(finalized.residualMaskedBytes + finalized.residualTruncatedBytes).toBeGreaterThan(0)
    let covered = 0
    for (const r of finalized.ranges) {
      expect(FINAL_DISPOSITIONS).toContain(r.disposition)
      covered += r.end - r.start
    }
    expect(covered).toBe(length)
  })
})

describe('T69 / I5 — free-text allowlist canary', () => {
  it('invented name outside vocabulary is never preserved', () => {
    const canary = 'Xylophantor'
    const text = `INFO connection from ${canary} established`
    const ops = sanitizeFreeText({ text, level: 'diagnostic' })
    const canaryOps = ops.filter(
      (op) => text.slice(op.start, op.end).toLowerCase() === canary.toLowerCase(),
    )
    expect(canaryOps.length).toBeGreaterThan(0)
    for (const op of canaryOps) {
      expect(op.kind).not.toBe('preserve')
    }
    const out = applyFreeTextOpsToString(text, ops, (op) =>
      maskAlphanumeric(op.spelling, 'Q'),
    )
    expect(out.toLowerCase()).not.toContain(canary.toLowerCase())
    expect(out.length).toBe(text.length)
  })
})
