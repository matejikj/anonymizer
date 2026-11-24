import type { Page } from '@playwright/test'
import { serializeMappingBundleJson } from '../../../src/mapping/bundle/index.ts'
import type { MappingBundlePayload } from '../../../src/mapping/bundle/types.ts'

/** A tiny, valid mapping bundle — just enough to exercise the resolve-only lookup screen. */
export function buildSampleMappingBundle(): MappingBundlePayload {
  return {
    sessionId: 'e2e-sample',
    canonicalizationVersion: 1,
    mappingRevision: 1,
    sources: [{ id: 'a', kind: 'text', name: 'sample.log' }],
    entries: [
      { identityId: 1, category: 'ip', canonical: '10.0.0.42', alias: '203.0.113.9', disposition: 'bijective', occurrenceCount: 5 },
      { identityId: 2, category: 'hostname', canonical: 'db-prod-1.internal', alias: 'host-1.example.invalid', disposition: 'bijective', occurrenceCount: 3 },
    ],
  }
}

/**
 * Sets a mapping bundle file directly on the resolve-only landing panel's file input —
 * equivalent to a user clicking the dropzone and choosing a file in the native picker, without
 * needing Playwright's filechooser interception (the input already exists in the DOM; this
 * bypasses the OS dialog the same way `setInputFiles` always does).
 */
export async function chooseMappingBundleFromLanding(page: Page): Promise<void> {
  const json = serializeMappingBundleJson(buildSampleMappingBundle())
  await page.getByTestId('resolve-return-file-input').setInputFiles({
    name: 'sample.rnd-mapping-bundle.json',
    mimeType: 'application/json',
    buffer: Buffer.from(json),
  })
}
