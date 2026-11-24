import { IconCheck, IconCircle, IconDot, IconWarning, IconX } from './icons.tsx'

export type StatusChipTone = 'ok' | 'warn' | 'error' | 'duplicate' | 'active' | 'waiting'

export interface StatusChipProps {
  readonly tone: StatusChipTone
  readonly label: string
  readonly compact?: boolean
  readonly className?: string
  readonly testId?: string
}

function StatusIcon({ tone }: { readonly tone: StatusChipTone }) {
  switch (tone) {
    case 'ok':
      return <IconCheck className="status-chip__icon" />
    case 'error':
      return <IconX className="status-chip__icon" />
    case 'duplicate':
    case 'warn':
      return <IconWarning className="status-chip__icon" />
    case 'active':
      return <IconDot className="status-chip__icon" />
    case 'waiting':
      return <IconCircle className="status-chip__icon" />
  }
}

export function StatusChip({ tone, label, compact, className, testId }: StatusChipProps) {
  return (
    <span
      className={`status-chip status-chip--${tone}${compact ? ' status-chip--compact' : ''}${className ? ` ${className}` : ''}`}
      data-testid={testId}
      data-status-icon={tone}
    >
      <StatusIcon tone={tone} />
      {compact ? null : <span className="status-chip__label">{label}</span>}
    </span>
  )
}
