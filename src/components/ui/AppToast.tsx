import { useAppStore } from '../../app/store.ts'
import { Button } from '../../design-system/index.ts'
import { undoDeleteRule } from '../../features/rules/ruleActions.ts'

export function AppToast() {
  const toast = useAppStore((s) => s.toast)
  if (!toast) return null

  return (
    <div className="app-toast" role="status" aria-live="polite" data-testid="app-toast">
      <span>{toast.message}</span>
      {toast.undoLabel && toast.kind === 'rule-undo' ? (
        <Button
          variant="ghost"
          data-testid="toast-undo"
          onClick={() => {
            useAppStore.getState().setPlanBusy(true)
            void undoDeleteRule()
              .finally(() => {
                useAppStore.getState().setPlanBusy(false)
                useAppStore.getState().bumpSessionEpoch()
              })
          }}
        >
          {toast.undoLabel}
        </Button>
      ) : null}
    </div>
  )
}
