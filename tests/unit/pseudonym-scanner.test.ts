import { describe, expect, it } from 'vitest'
import type { MappingBundlePayload } from '../../src/mapping/bundle/types'
import { AliasLookupIndex, scanReportForPseudonyms } from '../../src/mapping/resolve'

function buildPayload(entryCount: number): MappingBundlePayload {
  const entries = []
  for (let i = 0; i < entryCount; i++) {
    entries.push({
      identityId: i + 1,
      category: 'ip' as const,
      canonical: `10.0.${Math.floor(i / 256)}.${i % 256}`,
      alias: `anon-ip-${i}`,
      disposition: 'bijective' as const,
      occurrenceCount: 1,
    })
  }
  return {
    sessionId: 'bench',
    canonicalizationVersion: 1,
    mappingRevision: 1,
    sources: [],
    entries,
  }
}

function buildReport(sizeChars: number, token: string): string {
  const pad = 'x'.repeat(Math.max(0, sizeChars - token.length))
  return `${pad}${token}${pad}`
}

function naiveScan(report: string, aliases: readonly string[]): number {
  let hits = 0
  for (const alias of aliases) {
    if (!alias) continue
    let idx = 0
    while ((idx = report.indexOf(alias, idx)) !== -1) {
      hits++
      idx += 1
    }
  }
  return hits
}

describe('Stage 22 pseudonym scanner', () => {
  it('finds embedded pseudonyms in AI report text', () => {
    const payload = buildPayload(3)
    const index = AliasLookupIndex.fromBundlePayload(payload)
    const report = 'Summary: host anon-ip-1 contacted anon-ip-2 repeatedly.'
    const scan = scanReportForPseudonyms(report, index)
    expect(scan.findings.length).toBeGreaterThanOrEqual(2)
    expect(scan.findings.some((f) => f.alias === 'anon-ip-1')).toBe(true)
    expect(scan.findings.some((f) => f.alias === 'anon-ip-2')).toBe(true)
  })

  it('scan cost grows with mapping size for naive scan, not for Aho-Corasick', () => {
    const reportSize = 30_000
    const smallPayload = buildPayload(120)
    const largePayload = buildPayload(3_000)
    const smallIndex = AliasLookupIndex.fromBundlePayload(smallPayload)
    const largeIndex = AliasLookupIndex.fromBundlePayload(largePayload)
    const token = smallIndex.allAliases()[60]!
    const report = buildReport(reportSize, token)

    const measure = (fn: () => void, repeats = 5): number => {
      fn()
      const start = performance.now()
      for (let i = 0; i < repeats; i++) fn()
      return (performance.now() - start) / repeats
    }

    const acSmall = measure(() => scanReportForPseudonyms(report, smallIndex))
    const acLarge = measure(() => scanReportForPseudonyms(report, largeIndex))
    const naiveSmall = measure(() => naiveScan(report, smallIndex.allAliases()))
    const naiveLarge = measure(() => naiveScan(report, largeIndex.allAliases()))

    const acGrowth = acLarge / Math.max(acSmall, 0.001)
    const naiveGrowth = naiveLarge / Math.max(naiveSmall, 0.001)

    expect(acGrowth).toBeLessThan(8)
    expect(naiveGrowth).toBeGreaterThan(acGrowth * 1.5)
    expect(naiveGrowth).toBeGreaterThan(5)
  })
})
