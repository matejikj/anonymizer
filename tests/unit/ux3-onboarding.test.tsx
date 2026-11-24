/** @vitest-environment jsdom */
import { describe, expect, it, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FirstVisitTour } from '../../src/components/ui/FirstVisitTour.tsx'
import { useAppStore } from '../../src/app/store.ts'
import { resetOnboardingForTests } from '../../src/app/onboardingModel.ts'
import { cs } from '../../src/i18n/cs.ts'

describe('Sprint UX-3 first visit tour', () => {
  beforeEach(() => {
    resetOnboardingForTests()
    useAppStore.getState().resetSession()
    useAppStore.getState().setPhase('empty')
  })

  it('shows anchored tour on empty screen and dismisses', async () => {
    const user = userEvent.setup()
    render(
      <>
        <div data-testid="multi-source-dropzone">drop</div>
        <button type="button" data-testid="choose-file">
          choose
        </button>
        <aside data-testid="empty-resolve-return">resolve</aside>
        <FirstVisitTour />
      </>,
    )

    expect(await screen.findByTestId('first-visit-tour')).toBeInTheDocument()
    expect(screen.getByText(cs.onboarding.steps.dropzone.title)).toBeInTheDocument()

    await user.click(screen.getByTestId('first-visit-tour-next'))
    expect(screen.getByText(cs.onboarding.steps.multi.title)).toBeInTheDocument()

    await user.click(screen.getByTestId('first-visit-tour-next'))
    expect(screen.getByText(cs.onboarding.steps.export.title)).toBeInTheDocument()

    await user.click(screen.getByTestId('first-visit-tour-next'))
    expect(screen.queryByTestId('first-visit-tour')).not.toBeInTheDocument()
  })
})
