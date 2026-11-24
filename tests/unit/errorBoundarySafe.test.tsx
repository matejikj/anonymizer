/**
 * @vitest-environment happy-dom
 *
 * T03 — ErrorBoundary never renders Error.message with identity canaries.
 */

import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ErrorBoundary } from '../../src/components/ui/ErrorBoundary.tsx'

const CANARY = 'CANARY-BOUNDARY-2890844526123456789'

function Boom(): null {
  throw new Error(`No snapshot entry for ssrc:${CANARY}`)
}

describe('T03 ErrorBoundary', () => {
  it('shows safe detail without canary', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {})
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>,
    )
    const alert = screen.getByRole('alert')
    expect(alert.textContent).not.toContain(CANARY)
    expect(alert.textContent).toMatch(/Něco se pokazilo|Interní chyba|kód/i)
    spy.mockRestore()
  })
})
