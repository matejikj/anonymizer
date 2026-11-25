/**
 * Table tests: coverage disposition matrix for every preset × coverage status (step 1).
 */
import { describe, expect, it } from 'vitest'
import {
  DIAGNOSTIC_POLICY,
  HIGH_PRIVACY_POLICY,
  presetToSanitizationPolicy,
} from '../../../src/pcap/profile/presets'
import {
  resolveCoverageDisposition,
  type CoverageDisposition,
} from '../../../src/pcap/sanitize/coverageDisposition'
import type { CoverageStatus, SanitizationPolicy } from '../../../src/pcap/sanitize/types'

const STATUSES: readonly CoverageStatus[] = [
  'covered',
  'redacted',
  'encrypted',
  'unsupported',
  'malformed',
  'requires-reassembly',
  'heuristic',
  'preserved-unsafe',
  'preserved-for-diagnostics',
  'preserved-safe',
  'processing-failed',
  'truncated',
] as const

type Row = {
  readonly preset: SanitizationPolicy['preset']
  readonly status: CoverageStatus
  readonly layer: string
  readonly expected: CoverageDisposition
}

function rowsForPreset(
  policy: SanitizationPolicy,
  expected: Record<CoverageStatus, CoverageDisposition>,
  mediaExpected: CoverageDisposition,
): Row[] {
  const generic = STATUSES.map((status) => ({
    preset: policy.preset,
    status,
    layer: 'generic',
    expected: expected[status]!,
  }))
  const media = STATUSES.filter(
    (s) =>
      s !== 'covered'
      && s !== 'redacted'
      && s !== 'truncated'
      && s !== 'malformed'
      && s !== 'requires-reassembly'
      // Proven constants and already fail-closed spans retain their dispositions.
      && s !== 'preserved-for-diagnostics'
      && s !== 'preserved-safe'
      && s !== 'processing-failed',
  ).map(
    (status) => ({
      preset: policy.preset,
      status,
      layer: 'rtp',
      expected: mediaExpected,
    }),
  )
  return [...generic, ...media]
}

const MATRIX: readonly Row[] = [
  ...rowsForPreset(
    DIAGNOSTIC_POLICY,
    {
      covered: 'keep',
      redacted: 'keep',
      truncated: 'keep',
      encrypted: 'preserve-encrypted',
      unsupported: 'mask-in-place',
      malformed: 'mask-application-in-place',
      'requires-reassembly': 'mask-in-place',
      heuristic: 'mask-in-place',
      'preserved-unsafe': 'preserve-unsafe',
      'preserved-for-diagnostics': 'keep',
      'preserved-safe': 'keep',
      'processing-failed': 'keep',
    },
    'strip-media-payload',
  ),
  ...rowsForPreset(
    HIGH_PRIVACY_POLICY,
    {
      covered: 'keep',
      redacted: 'keep',
      truncated: 'keep',
      encrypted: 'preserve-encrypted',
      unsupported: 'truncate',
      malformed: 'drop',
      'requires-reassembly': 'truncate',
      heuristic: 'truncate',
      'preserved-unsafe': 'preserve-unsafe',
      'preserved-for-diagnostics': 'keep',
      'preserved-safe': 'keep',
      'processing-failed': 'keep',
    },
    'drop',
  ),
]

describe('coverage disposition matrix (diagnostic step 1)', () => {
  it.each(MATRIX)(
    '$preset / $status / $layer → $expected',
    ({ preset, status, layer, expected }) => {
      const policy = presetToSanitizationPolicy(preset)
      expect(resolveCoverageDisposition(policy, status, layer)).toBe(expected)
    },
  )

  it('diagnostic declares mask + strip-payload invariants', () => {
    expect(DIAGNOSTIC_POLICY.unsupportedPayloadPolicy).toBe('mask-in-place')
    expect(DIAGNOSTIC_POLICY.malformedPayloadPolicy).toBe('mask-application-in-place')
    expect(DIAGNOSTIC_POLICY.mediaPolicy).toBe('strip-payload')
    expect(DIAGNOSTIC_POLICY.preservePacketLengths).toBe(true)
    expect(DIAGNOSTIC_POLICY.preservePacketOrder).toBe(true)
    expect(DIAGNOSTIC_POLICY.truncateUnsupported).toBe(false)
    expect(DIAGNOSTIC_POLICY.dropMalformed).toBe(false)
  })

  it('high-privacy stays truncate/drop oriented', () => {
    expect(HIGH_PRIVACY_POLICY.unsupportedPayloadPolicy).toBe('truncate')
    expect(HIGH_PRIVACY_POLICY.mediaPolicy).toBe('drop')
  })
})
