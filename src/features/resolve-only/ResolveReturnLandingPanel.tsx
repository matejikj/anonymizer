import { useId, useRef } from 'react'
import { cs } from '../../i18n/cs.ts'
import { enterResolveOnly } from '../../app/sessionLifecycleCoordinator.ts'
import { selectResolveReturnBundle } from './resolveReturnController.ts'
import { Button } from '../../design-system/Button.tsx'

/**
 * Landing utility — open mapping-bundle picker (resolve-only). Secondary to anonymize hero.
 */
export function ResolveReturnLandingPanel() {
  const fileRef = useRef<HTMLInputElement>(null)
  const inputId = useId()

  const openPicker = () => fileRef.current?.click()

  return (
    <div className="empty__utility-item" data-testid="resolve-return-landing-panel">
      <label className="visually-hidden" htmlFor={inputId}>
        {cs.resolveReturn.chooseBundle}
      </label>
      <input
        id={inputId}
        ref={fileRef}
        type="file"
        accept=".rnd-mapping-bundle.json,application/json"
        className="visually-hidden"
        data-testid="resolve-return-file-input"
        onChange={(e) => {
          const file = e.target.files?.[0]
          e.target.value = ''
          if (!file) return
          enterResolveOnly()
          void selectResolveReturnBundle(file)
        }}
      />
      <Button
        variant="link"
        onClick={openPicker}
        data-testid="empty-resolve-return-open"
        aria-label={cs.resolveReturn.emptyAction}
      >
        {cs.resolveReturn.chooseBundle}
      </Button>
      {/* Legacy test hook — same control as the link above. */}
      <span className="visually-hidden" data-testid="resolve-return-landing-open">
        {cs.resolveReturn.chooseBundle}
      </span>
    </div>
  )
}
