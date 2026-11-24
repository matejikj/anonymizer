/** @vitest-environment jsdom */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import App from '../../src/App.tsx'
import { cs } from '../../src/i18n/cs.ts'

describe('App shell', () => {
  it('renders Czech empty state without login', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: cs.empty.landingLead })).toBeInTheDocument()
    expect(screen.getAllByText(cs.privacyBadge).length).toBeGreaterThanOrEqual(1)
    expect(screen.getByLabelText(cs.a11y.dropzone)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /přihlás/i })).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/heslo|password|login/i)).not.toBeInTheDocument()
  })

  it('exposes a skip link as the first tab stop', async () => {
    const user = userEvent.setup()
    render(<App />)
    const skip = screen.getByRole('link', { name: cs.skipToContent })
    expect(skip).toHaveAttribute('href', '#main')
    await user.tab()
    expect(skip).toHaveFocus()
  })

  it('keeps the dropzone keyboard reachable', async () => {
    const user = userEvent.setup()
    render(<App />)
    const dropzone = screen.getByLabelText(cs.a11y.dropzone)
    dropzone.focus()
    expect(dropzone).toHaveFocus()
    await user.keyboard('{Enter}')
    // Enter opens the file picker; shell remains mounted.
    expect(screen.getByRole('heading', { name: cs.empty.landingLead })).toBeInTheDocument()
  })
})
