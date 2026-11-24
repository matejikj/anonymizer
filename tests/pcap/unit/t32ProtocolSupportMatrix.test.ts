/**
 * T32 — protocol support matrix drift + support-request leak guard.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  APPLICATION_HANDLER_ORDER,
} from '../../../src/pcap/kernel/applicationHandlers.ts'
import { listCatalogProtocols } from '../../../src/pcap/kernel/catalog.ts'
import { UNSUPPORTED_PROTOCOL_NAMES } from '../../../src/pcap/sanitize/unsupportedIdentification.ts'
import {
  buildProtocolSupportMatrix,
  buildSupportRequestClipboard,
  protocolMatrixMarkers,
  supportRequestUserMessage,
} from '../../../src/pcap/docs/protocolSupportMatrix.ts'
import {
  collectMatrixConformanceViolations,
  resolveEffectiveAppHandlerFlags,
  VARIANT_CONFORMANCE_SPECS,
} from '../../../src/pcap/docs/protocolMatrixVariantConformance.ts'
import { buildAnonymizationOutcome } from '../../../src/pcap/coverage/anonymizationOutcome.ts'
import type { PcapProtocolCoverageRow } from '../../../src/pcap/coverage/pcapCoverageViewModel.ts'
import type { PcapPlanSnapshot } from '../../../src/pcap/export/planSnapshot.ts'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..')

describe('T32 protocol support matrix', () => {
  it('covers catalog, app handlers, and unsupported identify names', () => {
    const rows = buildProtocolSupportMatrix()
    const ids = new Set(rows.map((r) => r.id))
    for (const p of listCatalogProtocols()) {
      expect(ids.has(`catalog:${p.id}`), `missing catalog ${p.id}`).toBe(true)
    }
    for (const h of APPLICATION_HANDLER_ORDER) {
      expect(ids.has(`app:${h.id}`), `missing app ${h.id}`).toBe(true)
    }
    for (const name of UNSUPPORTED_PROTOCOL_NAMES) {
      expect(ids.has(`unsupported:${name}`), `missing unsupported ${name}`).toBe(true)
    }
    expect(rows.some((r) => r.protection === 'identify-mask')).toBe(true)
    expect(rows.some((r) => r.id === 'app:tls' && r.provenCiphertext)).toBe(true)
  })

  it('OpenVPN row stays mask-only without proven ciphertext (T28/R02 honesty)', () => {
    const ovpn = buildProtocolSupportMatrix().find((r) => r.id === 'app:openvpn')
    expect(ovpn?.protection).toBe('mask-only')
    expect(ovpn?.provenCiphertext).toBe(false)
    expect(ovpn?.structured).toBe(false)
  })

  it('QUIC and DTLS rows stay mask-only without structured or proven ciphertext (T28 overclaim guard)', () => {
    const rows = buildProtocolSupportMatrix()
    for (const id of ['app:quic', 'app:dtls'] as const) {
      const row = rows.find((r) => r.id === id)
      expect(row?.protection, id).toBe('mask-only')
      expect(row?.structured, id).toBe(false)
      expect(row?.provenCiphertext, id).toBe(false)
    }
  })

  it('variant conformance contract rejects missing evidence and validates registered modules', () => {
    const violations = collectMatrixConformanceViolations(root, (p) => fs.readFileSync(p, 'utf8'))
    expect(violations, violations.map((v) => `${v.handlerId}: ${v.message}`).join('\n')).toEqual([])
  })

  it('conformance ceiling blocks structured claims even when notes would allow encrypted-phase', () => {
    for (const handlerId of Object.keys(VARIANT_CONFORMANCE_SPECS)) {
      const effective = resolveEffectiveAppHandlerFlags(handlerId, {
        protection: 'encrypted-phase',
        provenCiphertext: true,
      })
      expect(effective.structured, handlerId).toBe(false)
      expect(effective.provenCiphertext, handlerId).toBe(false)
      expect(effective.protection, handlerId).toBe('mask-only')
    }
  })

  it('application rows keep structured/provenCiphertext aligned with effective protection', () => {
    for (const row of buildProtocolSupportMatrix()) {
      if (!row.id.startsWith('app:')) continue
      if (row.protection === 'mask-only' || row.protection === 'identify-mask') {
        expect(row.structured, row.id).toBe(false)
        expect(row.provenCiphertext, row.id).toBe(false)
      }
      if (row.provenCiphertext) {
        expect(row.protection, row.id).toBe('encrypted-phase')
        expect(row.structured, row.id).toBe(true)
      }
    }
  })

  it('keeps the reference matrix in protocolSupportMatrix.ts without duplicating it in the explanatory overview', () => {
    const overview = fs.readFileSync(path.join(root, 'docs/PCAP_ANONYMIZATION_OVERVIEW.md'), 'utf8')
    expect(overview).toContain('protocolSupportMatrix.ts')
    expect(overview).not.toContain(protocolMatrixMarkers().start)
    expect(overview).not.toMatch(/^\|/m)
  })

  it('support request clipboard has codes/counts only — no canary payload', () => {
    const canary = 'SECRET-USER@example.com-10.1.2.3'
    const text = buildSupportRequestClipboard([
      { code: 'unsupported:ssdp', family: 'SSDP (pravděpodobně)', packetCount: 12, flowCount: 3 },
    ])
    expect(text).toContain('unsupported:ssdp')
    expect(text).toContain('12 paketů')
    expect(text).toContain('3 toků')
    expect(text.includes(canary)).toBe(false)
    expect(text.toLowerCase()).not.toContain('example.com')
    expect(supportRequestUserMessage({
      code: 'unsupported:ssdp',
      family: 'x',
      packetCount: 12,
      flowCount: 0,
    })).toMatch(/bez souboru/)
  })

  it('outcome exposes support requests for unsupported protocols', () => {
    const protocols: PcapProtocolCoverageRow[] = [
      {
        protocol: 'unsupported:ssdp',
        familyId: 'identified-unsupported',
        familyLabel: 'SSDP',
        probableIdentification: true,
        recognizedPacketCount: 7,
        protectedPacketCount: 7,
        layerKind: 'both',
        dominantStatus: 'unsupported',
        dominantUiStatus: 'unsupported',
        userVerdict: 'protected-export-no-full-analysis',
        userVerdictLabel: 'x',
        technicalSourceLabel: 'x',
        unsupportedCount: 7,
        filterProtocol: 'unsupported:ssdp',
      },
    ]
    const plan = {
      packets: [],
      incidents: null,
    } as unknown as PcapPlanSnapshot
    const outcome = buildAnonymizationOutcome({
      protocols,
      gate: 'AI_READY_WITH_GAPS',
      plan,
      preset: 'diagnostic',
    })
    expect(outcome.supportRequests).toHaveLength(1)
    expect(outcome.supportRequests[0]?.code).toBe('unsupported:ssdp')
    expect(outcome.supportRequests[0]?.packetCount).toBe(7)
    expect(outcome.supportRequests[0]?.clipboardText).toContain('unsupported:ssdp')
  })
})
