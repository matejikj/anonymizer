import type { ReactNode } from 'react'
import { Button } from './Button.tsx'
import { IconButton } from './IconButton.tsx'
import { IconMore } from '../components/ui/icons.tsx'

/**
 * File-level workspace chrome (DESIGN_MOVES step 2).
 *
 * Contract:
 * - surface: opaque `surface-2`, flat bottom border (no glass card)
 * - slots L→R: context · tools · status · primary · overflow
 * - embedded: tools (+ optional context file name); no open/close/set export
 */
export function WorkspaceChrome({
  context,
  tools,
  status,
  primary,
  overflow,
  embedded = false,
  className,
  testId,
  mode,
}: {
  readonly context?: ReactNode
  readonly tools?: ReactNode
  readonly status?: ReactNode
  readonly primary?: ReactNode
  readonly overflow?: ReactNode
  readonly embedded?: boolean
  readonly className?: string
  readonly testId?: string
  /** Optional mode attribute for tests (e.g. standalone | embedded). */
  readonly mode?: string
}) {
  return (
    <CommandBar
      className={['workspace-chrome', embedded ? 'workspace-chrome--embedded' : null, className]
        .filter(Boolean)
        .join(' ')}
      testId={testId}
      mode={mode}
      context={context}
      tools={tools}
      status={status}
      primary={primary}
      overflow={overflow}
    />
  )
}

/**
 * Workspace command bar pattern (Stage 8.3 / DESIGN_MOVES step 2):
 * context → tools → status → primary → overflow
 */
export function CommandBar({
  context,
  status,
  tools,
  primary,
  overflow,
  className,
  testId,
  mode,
}: {
  readonly context?: ReactNode
  readonly status?: ReactNode
  readonly tools?: ReactNode
  readonly primary?: ReactNode
  readonly overflow?: ReactNode
  readonly className?: string
  readonly testId?: string
  readonly mode?: string
}) {
  return (
    <div
      className={['ds-command-bar', 'command-strip', className].filter(Boolean).join(' ')}
      data-testid={testId}
      data-mode={mode}
      role="toolbar"
    >
      {context ? <div className="ds-command-bar__context">{context}</div> : null}
      {tools ? <div className="ds-command-bar__tools">{tools}</div> : null}
      {status ? <div className="ds-command-bar__status">{status}</div> : null}
      {primary ? <div className="ds-command-bar__primary">{primary}</div> : null}
      {overflow ? <div className="ds-command-bar__overflow">{overflow}</div> : null}
    </div>
  )
}

export function CommandBarOverflowMenu({
  label,
  open,
  onToggle,
  children,
}: {
  readonly label: string
  readonly open: boolean
  readonly onToggle: (open: boolean) => void
  readonly children: ReactNode
}) {
  return (
    <details
      className="command-strip__more"
      open={open}
      onToggle={(e) => onToggle((e.target as HTMLDetailsElement).open)}
    >
      <summary className="btn btn--ghost btn--tiny" aria-label={label}>
        <IconMore size={16} />
      </summary>
      <div className="command-strip__more-panel" role="menu">
        {children}
      </div>
    </details>
  )
}

export function FilterBar({
  children,
  label,
  className,
}: {
  readonly children: ReactNode
  readonly label: string
  readonly className?: string
}) {
  return (
    <div className={['ds-filter-bar', className].filter(Boolean).join(' ')} role="group" aria-label={label}>
      {children}
    </div>
  )
}

export function StatusSummary({
  children,
  className,
  testId,
}: {
  readonly children: ReactNode
  readonly className?: string
  readonly testId?: string
}) {
  return (
    <div className={['ds-status-summary', className].filter(Boolean).join(' ')} data-testid={testId}>
      {children}
    </div>
  )
}

export function EmptyState({
  title,
  body,
  actions,
  className,
  testId,
}: {
  readonly title: string
  readonly body?: string
  readonly actions?: ReactNode
  readonly className?: string
  readonly testId?: string
}) {
  return (
    <section className={['ds-empty-state', className].filter(Boolean).join(' ')} data-testid={testId}>
      <h2 className="ds-empty-state__title">{title}</h2>
      {body ? <p className="ds-empty-state__body">{body}</p> : null}
      {actions}
    </section>
  )
}

export function ErrorState({
  title,
  body,
  actions,
  className,
  testId,
}: {
  readonly title: string
  readonly body?: string
  readonly actions?: ReactNode
  readonly className?: string
  readonly testId?: string
}) {
  return (
    <section
      className={['ds-error-state', className].filter(Boolean).join(' ')}
      role="alert"
      data-testid={testId}
    >
      <h2 className="ds-error-state__title">{title}</h2>
      {body ? <p className="ds-error-state__body">{body}</p> : null}
      {actions}
    </section>
  )
}

export function LoadingState({
  title,
  body,
  className,
  testId,
}: {
  readonly title: string
  readonly body?: string
  readonly className?: string
  readonly testId?: string
}) {
  return (
    <section
      className={['ds-loading-state', className].filter(Boolean).join(' ')}
      aria-busy="true"
      data-testid={testId}
    >
      <h2 className="ds-loading-state__title">{title}</h2>
      {body ? <p className="ds-loading-state__body">{body}</p> : null}
    </section>
  )
}

export function FileRow({
  name,
  meta,
  trailing,
  className,
}: {
  readonly name: string
  readonly meta?: string
  readonly trailing?: ReactNode
  readonly className?: string
}) {
  return (
    <div className={['ds-file-row', className].filter(Boolean).join(' ')}>
      <span className="ds-file-row__name">{name}</span>
      {meta ? <span className="ds-file-row__meta">{meta}</span> : null}
      {trailing}
    </div>
  )
}

export function EntityRow({
  label,
  meta,
  trailing,
  className,
}: {
  readonly label: string
  readonly meta?: string
  readonly trailing?: ReactNode
  readonly className?: string
}) {
  return (
    <div className={['ds-entity-row', className].filter(Boolean).join(' ')}>
      <span className="ds-entity-row__label">{label}</span>
      {meta ? <span className="ds-entity-row__meta">{meta}</span> : null}
      {trailing}
    </div>
  )
}

export function ExportSummary({
  children,
  className,
  testId,
}: {
  readonly children: ReactNode
  readonly className?: string
  readonly testId?: string
}) {
  return (
    <div className={['ds-export-summary', className].filter(Boolean).join(' ')} data-testid={testId}>
      {children}
    </div>
  )
}

export { Button, IconButton }
