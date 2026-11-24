/** @vitest-environment jsdom */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MultiSourceDropzone } from '../../src/features/correlation-staging/MultiSourceDropzone.tsx'
import { useAppStore } from '../../src/app/store.ts'
import { beforeEach } from 'vitest'

describe('DESIGN_MOVES step 1 — landing hero + utilities', () => {
  beforeEach(() => {
    useAppStore.getState().resetSession()
  })

  it('renders a single primary dropzone and utility strip without side panels', () => {
    render(<MultiSourceDropzone />)
    expect(screen.getByTestId('landing')).toBeInTheDocument()
    expect(screen.getByTestId('landing-anonymize-panel')).toBeInTheDocument()
    expect(screen.getAllByTestId('multi-source-dropzone')).toHaveLength(1)
    expect(screen.getByTestId('landing-utilities')).toBeInTheDocument()
    expect(screen.getByTestId('resolve-return-landing-panel')).toBeInTheDocument()
    expect(screen.getByTestId('recovery-landing-panel')).toBeInTheDocument()
    expect(document.querySelector('.empty__split')).toBeNull()
    expect(document.querySelector('.empty__panel--resolve')).toBeNull()
    expect(document.querySelector('.empty__panel--recovery')).toBeNull()
    expect(document.querySelector('.dropzone--resolve')).toBeNull()
    expect(document.querySelector('.dropzone--recovery')).toBeNull()
  })
})
