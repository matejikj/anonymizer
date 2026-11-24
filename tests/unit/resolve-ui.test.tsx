/** @vitest-environment jsdom */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ResolveWorkspacePanel } from '../../src/features/resolve-only/ResolveWorkspacePanel'
import type { MappingBundlePayload } from '../../src/mapping/bundle/types'

const payload: MappingBundlePayload = {
  sessionId: 'ui',
  canonicalizationVersion: 1,
  mappingRevision: 1,
  sources: [],
  entries: [
    {
      identityId: 1,
      category: 'ip',
      canonical: '10.0.0.42',
      alias: '203.0.113.9',
      disposition: 'bijective',
      occurrenceCount: 1,
    },
  ],
}

describe('Stage 22 resolve workspace UI', () => {
  it('annotated report appears only after explicit annotate action', async () => {
    const user = userEvent.setup()
    render(<ResolveWorkspacePanel source="imported-bundle" bundlePayload={payload} />)

    const reportInput = screen.getByTestId('resolve-report-input')
    await user.clear(reportInput)
    await user.type(reportInput, 'Host 203.0.113.9 failed health check.')

    await user.click(screen.getByTestId('resolve-scan-submit'))
    expect(screen.getByTestId('resolve-scan-summary')).toBeTruthy()
    expect(screen.queryByTestId('resolve-annotated-output')).toBeNull()

    await user.click(screen.getByTestId('resolve-annotate-submit'))
    expect(screen.getByTestId('resolve-annotated-output')).toBeTruthy()
    const annotated = screen.getByTestId('resolve-annotated-output').querySelector('textarea')
    expect(annotated?.value).toContain('10.0.0.42')
  })
})
