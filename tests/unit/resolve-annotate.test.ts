import { describe, expect, it } from 'vitest'
import { buildAnnotatedReport, scanReportForPseudonyms, AliasLookupIndex } from '../../src/mapping/resolve'
import type { MappingBundlePayload } from '../../src/mapping/bundle/types'

const payload: MappingBundlePayload = {
  sessionId: 'a',
  canonicalizationVersion: 1,
  mappingRevision: 1,
  sources: [],
  entries: [
    {
      identityId: 1,
      category: 'ip',
      canonical: '10.0.0.1',
      alias: '192.0.2.1',
      disposition: 'bijective',
      occurrenceCount: 1,
    },
  ],
}

describe('Stage 22 annotated report', () => {
  it('does not mutate report until annotate is explicitly invoked', () => {
    const index = AliasLookupIndex.fromBundlePayload(payload)
    const report = 'Traffic from 192.0.2.1 was blocked.'
    const scan = scanReportForPseudonyms(report, index)
    expect(scan.findings.length).toBeGreaterThan(0)

    expect(report).toBe('Traffic from 192.0.2.1 was blocked.')

    const annotated = buildAnnotatedReport(report, scan.findings, {
      ambiguousLabel: 'nelze určit jednoznačně',
    })
    expect(annotated).toContain('10.0.0.1')
    expect(annotated).not.toBe(report)
  })

  it('marks ambiguous fixed replacements in annotated output', () => {
    const ambiguous: MappingBundlePayload = {
      ...payload,
      entries: [
        {
          identityId: 1,
          category: 'custom',
          canonical: 'one',
          alias: '[REDACTED]',
          disposition: 'ambiguous-fixed',
          occurrenceCount: 1,
        },
        {
          identityId: 2,
          category: 'custom',
          canonical: 'two',
          alias: '[REDACTED]',
          disposition: 'ambiguous-fixed',
          occurrenceCount: 1,
        },
      ],
    }
    const index = AliasLookupIndex.fromBundlePayload(ambiguous)
    const report = 'Value [REDACTED] appeared twice.'
    const scan = scanReportForPseudonyms(report, index)
    const annotated = buildAnnotatedReport(report, scan.findings, {
      ambiguousLabel: 'nelze určit jednoznačně',
    })
    expect(annotated).toContain('nelze určit jednoznačně')
    expect(annotated).toContain('one')
    expect(annotated).toContain('two')
  })
})
