/** @vitest-environment jsdom */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ErrorBoundary } from '../../src/components/ui/ErrorBoundary.tsx'
import { cs } from '../../src/i18n/cs.ts'

function Boom(): null {
  throw new Error('boom-test')
}

describe('ErrorBoundary', () => {
  it('shows Czech recovery UI', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    )
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: cs.errors.boundaryTitle })).toBeInTheDocument()
    expect(screen.getByText(cs.errors.boundaryBody)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: cs.errors.boundaryRetry })).toBeInTheDocument()
    spy.mockRestore()
  })
})
