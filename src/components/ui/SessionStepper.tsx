import { useAppStore } from '../../app/store.ts'
import { usePcapStore } from '../../pcap/ui/pcapStore.ts'
import { resolveSessionStepView, SESSION_STEP_ORDER } from '../../app/sessionStepModel.ts'
import { cs } from '../../i18n/cs.ts'

export function SessionStepper() {
  const phase = useAppStore((s) => s.phase)
  const activeMode = useAppStore((s) => s.activeMode)
  const pcapPhase = usePcapStore((s) => s.phase)
  const inPcapShell = activeMode === 'pcap'
  const stepView = resolveSessionStepView(phase, pcapPhase, inPcapShell)

  if (!stepView.visible || !stepView.activeStep) return null

  return (
    <nav
      className="session-stepper"
      aria-label={cs.sessionStepper.label}
      data-testid="session-stepper"
    >
      <ol className="session-stepper__list">
        {SESSION_STEP_ORDER.map((id, index) => {
          const active = stepView.activeStep === id
          const done = stepView.completedBefore.has(id)
          const label = cs.sessionStepper.steps[id]
          return (
            <li
              key={id}
              className={`session-stepper__item${active ? ' session-stepper__item--active' : ''}${done ? ' session-stepper__item--done' : ''}`}
              aria-current={active ? 'step' : undefined}
              aria-label={
                active
                  ? `${index + 1}/${SESSION_STEP_ORDER.length}: ${label}`
                  : done
                    ? `${label} — hotovo`
                    : label
              }
              data-testid={`session-step-${id}`}
            >
              {index > 0 ? <span className="session-stepper__rail" aria-hidden="true" /> : null}
              <span className="session-stepper__dot" aria-hidden="true" />
              <span className="session-stepper__label">{label}</span>
            </li>
          )
        })}
      </ol>
    </nav>
  )
}
