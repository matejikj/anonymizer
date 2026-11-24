/** @vitest-environment jsdom */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { beforeEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MultiSourceDropzone } from '../../src/features/correlation-staging/MultiSourceDropzone.tsx'
import { useAppStore } from '../../src/app/store.ts'
import { cs } from '../../src/i18n/cs.ts'

const root = process.cwd()

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

describe('FORENSIC_BENCH step 3 — landing bench empty', () => {
  beforeEach(() => {
    useAppStore.getState().resetSession()
  })

  it('composes one short title · one dropzone · utilities', () => {
    render(<MultiSourceDropzone />)
    expect(screen.getByTestId('landing')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: cs.empty.landingLead })).toHaveClass(
      'type-page-title',
    )
    expect(screen.queryByText(cs.appName)).not.toBeInTheDocument()
    expect(screen.queryByText(cs.empty.title)).not.toBeInTheDocument()
    expect(screen.getAllByTestId('multi-source-dropzone')).toHaveLength(1)
    expect(screen.getByTestId('landing-utilities')).toBeInTheDocument()
    expect(document.querySelector('.dropzone__format-badges')).toBeNull()
    expect(document.querySelector('.type-display')).toBeNull()
    expect(screen.getByText(cs.empty.dropzoneHint)).toBeInTheDocument()
  })

  it('uses one clickable dropzone as the file picker (no separate choose button)', () => {
    const landing = read('src/features/correlation-staging/MultiSourceDropzone.tsx')
    expect(landing).toContain('data-testid="multi-source-dropzone"')
    expect(landing).not.toMatch(/data-testid="choose-file"/)
    expect(landing).not.toMatch(/empty__primary-action/)
    expect(landing).not.toMatch(/\bBadge\b/)
  })

  it('unifies empty max-width to --space-content-max (42rem)', () => {
    const tokens = read('src/styles/tokens.css')
    const patterns = read('src/styles/patterns.css')
    const foundations = read('src/styles/foundations.css')
    expect(tokens).toMatch(/--space-content-max:\s*42rem/)
    expect(patterns).toMatch(/\.empty--landing \{[\s\S]*?max-width:\s*var\(--space-content-max\)/)
    expect(foundations).toMatch(/\.empty \{[\s\S]*?max-width:\s*var\(--space-content-max\)/)
    expect(patterns).not.toMatch(/64rem/)
    expect(foundations).not.toMatch(/64rem/)
  })

  it('styles hero dropzone as hairline raised (no dashed / no glow ring)', () => {
    const foundations = read('src/styles/foundations.css')
    expect(foundations).toMatch(
      /\.dropzone--hero \{[\s\S]*?border:\s*1px solid var\(--color-border-subtle\)/,
    )
    expect(foundations).not.toMatch(/\.dropzone--hero \{[\s\S]*?border:\s*1px dashed/)
  })
})
