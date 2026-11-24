/**
 * @vitest-environment node
 *
 * Step 10 — privacy / no-leak gate over golden seeds and sidecars.
 */

import { describe, expect, it } from 'vitest'
import { assertReportHasNoOriginalIdentifiers } from '../../../src/pcap/export/report'
import { diagnosticGoldenScenarios } from '../fixtures/diagnosticGoldenCorpus'
import { runDiagnosticExportPipeline } from '../helpers/diagnosticPipeline'
import {
  assertCaptureHasNoPrivacyLeaks,
  assertSidecarHasNoPrivacyLeaks,
  privacyLeakVariants,
} from '../helpers/privacyLeakScan'

describe('diagnostic privacy gate (step 10)', () => {
  for (const scenario of diagnosticGoldenScenarios()) {
    it(`no-leak raw+hex+base64+sidecar: ${scenario.id}`, () => {
      const { built, reportJson, aiDiagnosticsJson } = runDiagnosticExportPipeline(
        scenario.packets,
        `${scenario.id}.pcap`,
        `privacy-${scenario.id}`,
      )
      assertCaptureHasNoPrivacyLeaks(built.buffer, scenario.seeds)
      assertReportHasNoOriginalIdentifiers(reportJson)
      assertReportHasNoOriginalIdentifiers(aiDiagnosticsJson)
      assertSidecarHasNoPrivacyLeaks(reportJson, scenario.seeds)
      assertSidecarHasNoPrivacyLeaks(aiDiagnosticsJson, scenario.seeds)
    })
  }

  it('privacyLeakVariants includes hex encodings', () => {
    const variants = privacyLeakVariants(['AbCdEfGh'])
    expect(variants.some((v) => /^[0-9a-f]+$/i.test(v.replace(/[: ]/g, '')))).toBe(true)
  })
})
