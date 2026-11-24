/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MappingResolveWorkspace } from '../../src/features/resolve-only/MappingResolveWorkspace.tsx'
import { ResolveOnlyView } from '../../src/features/resolve-only/ResolveOnlyView.tsx'
import { ResolveWorkspacePanel } from '../../src/features/resolve-only/ResolveWorkspacePanel.tsx'
import { MultiSourceDropzone } from '../../src/features/correlation-staging/MultiSourceDropzone.tsx'
import { cs } from '../../src/i18n/cs.ts'
import { useAppStore } from '../../src/app/store.ts'
import { serializeMappingBundleJson } from '../../src/mapping/bundle/index.ts'
import {
  openResolveReturnFromEmpty,
  resetResolveReturnForTests,
  forceResolveReturnLookupStep,
} from '../../src/features/resolve-only/resolveReturnController.ts'
import { setResolveOnlyPayload, clearResolveOnlyModel, isResolveOnlyActive } from '../../src/features/resolve-only/resolveOnlyModel.ts'
import { importMappingBundleFile } from '../../src/features/mapping-bundle/bundleController.ts'
import type { MappingBundlePayload } from '../../src/mapping/bundle/types.ts'

const payload: MappingBundlePayload = {
  sessionId: 's30',
  canonicalizationVersion: 1,
  mappingRevision: 1,
  sources: [{ id: 'a', kind: 'text', name: 'a.log' }],
  entries: [
    {
      identityId: 1,
      category: 'ip',
      canonical: '10.0.0.42',
      alias: '203.0.113.9',
      disposition: 'bijective',
      occurrenceCount: 2,
    },
    {
      identityId: 2,
      category: 'ip',
      canonical: '10.0.0.99',
      alias: '[REDACTED]',
      disposition: 'ambiguous-fixed',
      occurrenceCount: 1,
    },
    {
      identityId: 3,
      category: 'ip',
      canonical: '10.0.0.100',
      alias: '[REDACTED]',
      disposition: 'ambiguous-fixed',
      occurrenceCount: 1,
    },
  ],
}

describe('Stage 30 MappingResolveWorkspace UI', () => {
  beforeEach(() => {
    resetResolveReturnForTests()
    clearResolveOnlyModel()
    useAppStore.getState().resetSession()
  })

  afterEach(() => {
    resetResolveReturnForTests()
    clearResolveOnlyModel()
  })

  it('empty state exposes resolve as a secondary landing utility', () => {
    render(<MultiSourceDropzone />)
    expect(screen.getByTestId('landing-anonymize-panel')).toBeInTheDocument()
    expect(screen.getByTestId('landing-utilities')).toBeInTheDocument()
    expect(screen.getByTestId('resolve-return-landing-panel')).toBeInTheDocument()
    expect(screen.getByTestId('recovery-landing-panel')).toBeInTheDocument()
    expect(screen.queryByTestId('multi-source-dropzone')).toBeInTheDocument()
    expect(screen.getByTestId('empty-resolve-return-open')).toHaveTextContent(cs.resolveReturn.chooseBundle)
    expect(document.querySelector('.dropzone--resolve')).toBeNull()
    expect(document.querySelector('.dropzone--recovery')).toBeNull()
  })

  it('CTA click alone only opens the file picker — no phase change until a file is chosen', async () => {
    const user = userEvent.setup()
    render(<MultiSourceDropzone />)
    await user.click(screen.getByTestId('empty-resolve-return-open'))
    expect(useAppStore.getState().phase).not.toBe('resolve-only')
  })

  it('choosing a file on the landing panel enters resolve-only and imports it directly', async () => {
    const user = userEvent.setup()
    render(<MultiSourceDropzone />)

    const json = serializeMappingBundleJson(payload)
    const file = new File([json], 'map.rnd-mapping-bundle.json', { type: 'application/json' })
    await user.upload(screen.getByTestId('resolve-return-file-input'), file)

    expect(useAppStore.getState().phase).toBe('resolve-only')
    await waitFor(() => expect(isResolveOnlyActive()).toBe(true))
  })

  it('wizard shows two steps and pick UI from empty open', () => {
    openResolveReturnFromEmpty()
    render(<MappingResolveWorkspace />)
    expect(screen.getByTestId('mapping-resolve-workspace')).toBeInTheDocument()
    expect(screen.getByTestId('resolve-return-pick')).toBeInTheDocument()
    expect(screen.getByTestId('resolve-return-close')).toHaveTextContent(cs.resolveReturn.closeClear)
  })

  it('shows lookup UI when bundle is unlocked but wizard step lagged', () => {
    openResolveReturnFromEmpty()
    setResolveOnlyPayload(payload, 'map.rnd-mapping-bundle.json')
    render(<MappingResolveWorkspace />)
    expect(screen.getByTestId('resolve-return-lookup')).toBeInTheDocument()
    expect(screen.queryByTestId('resolve-return-pick')).not.toBeInTheDocument()
  })

  it('JSON bundle import advances wizard to lookup UI', async () => {
    const json = serializeMappingBundleJson(payload)
    const file = new File([json], 'map.rnd-mapping-bundle.json', { type: 'application/json' })

    await importMappingBundleFile({ file })
    expect(isResolveOnlyActive()).toBe(true)

    openResolveReturnFromEmpty()
    setResolveOnlyPayload(payload, file.name)
    render(<ResolveOnlyView />)

    expect(screen.getByTestId('resolve-return-lookup')).toBeInTheDocument()
    expect(screen.queryByTestId('resolve-return-pick')).not.toBeInTheDocument()
    expect(screen.getByTestId('mapping-browse')).toBeInTheDocument()
    expect(screen.getByTestId('mapping-ai-report')).toBeInTheDocument()
  })

  it('masks originals by default and reveals on explicit action', async () => {
    const user = userEvent.setup()
    setResolveOnlyPayload(payload, 'map.bundle')
    forceResolveReturnLookupStep()
    render(<ResolveWorkspacePanel source="imported-bundle" bundlePayload={payload} />)

    const aliasInput = screen.getByTestId('resolve-alias-input')
    await user.clear(aliasInput)
    await user.click(aliasInput)
    await user.paste('203.0.113.9')
    await user.click(screen.getByTestId('resolve-exact-submit'))

    expect(screen.getByTestId('resolve-exact-result')).toBeInTheDocument()
    const masked = screen.getByTestId('resolve-masked-value')
    expect(masked.textContent).not.toContain('10.0.0.42')
    expect(masked.textContent).toMatch(/•/)

    await user.click(screen.getByTestId('resolve-reveal-original'))
    expect(screen.getByTestId('resolve-masked-value').textContent).toBe('10.0.0.42')
  })

  it('ambiguous fixed replacement shows all candidates', async () => {
    const user = userEvent.setup()
    render(<ResolveWorkspacePanel source="imported-bundle" bundlePayload={payload} />)
    const aliasInput = screen.getByTestId('resolve-alias-input')
    await user.clear(aliasInput)
    await user.click(aliasInput)
    await user.paste('[REDACTED]')
    await user.click(screen.getByTestId('resolve-exact-submit'))

    expect(screen.getByTestId('resolve-exact-ambiguous')).toBeInTheDocument()
    expect(screen.getAllByTestId('resolve-candidate')).toHaveLength(2)
  })

  it('browse table lists every entry, masked, with an ambiguous badge', () => {
    setResolveOnlyPayload(payload, 'map.bundle')
    forceResolveReturnLookupStep()
    render(<MappingResolveWorkspace />)

    expect(screen.getAllByTestId('mapping-browse-row')).toHaveLength(3)
    const masked = screen.getAllByTestId('resolve-masked-value')
    for (const el of masked) expect(el.textContent).not.toContain('10.0.0')
    expect(screen.getAllByText(cs.resolveReturn.dispositionAmbiguous)).toHaveLength(2)
  })

  it('browse search narrows the table to matching alias or original', async () => {
    const user = userEvent.setup()
    setResolveOnlyPayload(payload, 'map.bundle')
    forceResolveReturnLookupStep()
    render(<MappingResolveWorkspace />)

    const searchInput = screen.getByTestId('mapping-browse-search')
    await user.click(searchInput)
    await user.paste('[REDACTED]')
    expect(screen.getAllByTestId('mapping-browse-row')).toHaveLength(2)
    expect(screen.getAllByTestId('mapping-browse-alias').every((el) => el.textContent === '[REDACTED]')).toBe(true)
  })

  it('browse category chips filter the table', async () => {
    const user = userEvent.setup()
    const mixedPayload: MappingBundlePayload = {
      ...payload,
      entries: [
        ...payload.entries,
        {
          identityId: 4,
          category: 'hostname',
          canonical: 'db-prod-1.internal',
          alias: 'host-1.example.invalid',
          disposition: 'bijective',
          occurrenceCount: 3,
        },
      ],
    }
    setResolveOnlyPayload(mixedPayload, 'map.bundle')
    forceResolveReturnLookupStep()
    render(<MappingResolveWorkspace />)

    expect(screen.getAllByTestId('mapping-browse-row')).toHaveLength(4)
    await user.click(screen.getByTestId('mapping-browse-chip-hostname'))
    expect(screen.getAllByTestId('mapping-browse-row')).toHaveLength(1)
    expect(screen.getByTestId('mapping-browse-alias')).toHaveTextContent('host-1.example.invalid')
  })
})
