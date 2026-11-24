import type { ButtonHTMLAttributes, ReactNode } from 'react'

export interface SegmentedOption {
  readonly id: string
  readonly label: string
  readonly disabled?: boolean
}

export function SegmentedControl({
  options,
  value,
  onChange,
  label,
  className,
}: {
  readonly options: readonly SegmentedOption[]
  readonly value: string
  readonly onChange: (id: string) => void
  readonly label: string
  readonly className?: string
}) {
  return (
    <div className={['segmented', className].filter(Boolean).join(' ')} role="group" aria-label={label}>
      {options.map((opt) => (
        <button
          key={opt.id}
          type="button"
          className="segmented__btn"
          aria-pressed={value === opt.id}
          data-state={value === opt.id ? 'active' : 'default'}
          disabled={opt.disabled}
          onClick={() => onChange(opt.id)}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}

export interface TabItem {
  readonly id: string
  readonly label: string
  readonly disabled?: boolean
}

export function Tabs({
  tabs,
  value,
  onChange,
  label,
  className,
}: {
  readonly tabs: readonly TabItem[]
  readonly value: string
  readonly onChange: (id: string) => void
  readonly label: string
  readonly className?: string
}) {
  return (
    <div className={['tabs', className].filter(Boolean).join(' ')}>
      <div role="tablist" aria-label={label} className="tabs__list">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            className="tabs__tab"
            id={`tab-${tab.id}`}
            aria-selected={value === tab.id}
            aria-controls={`tabpanel-${tab.id}`}
            data-state={value === tab.id ? 'active' : 'default'}
            tabIndex={value === tab.id ? 0 : -1}
            disabled={tab.disabled}
            onClick={() => onChange(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {tabs.map((tab) =>
        value === tab.id ? (
          <div
            key={`panel-${tab.id}`}
            role="tabpanel"
            id={`tabpanel-${tab.id}`}
            aria-labelledby={`tab-${tab.id}`}
            className="tabs__panel"
          />
        ) : null,
      )}
    </div>
  )
}

export function Badge({
  children,
  tone = 'neutral',
  className,
}: {
  readonly children: ReactNode
  readonly tone?: 'neutral' | 'accent' | 'safe' | 'warn' | 'blocked'
  readonly className?: string
}) {
  return (
    <span className={['badge', `badge--${tone}`, className].filter(Boolean).join(' ')}>{children}</span>
  )
}

export function Progress({
  value,
  max = 100,
  label,
  className,
}: {
  readonly value: number
  readonly max?: number
  readonly label?: string
  readonly className?: string
}) {
  const pct = max <= 0 ? 0 : Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div className={['progress', className].filter(Boolean).join(' ')}>
      {label ? <p className="progress__label">{label}</p> : null}
      <div
        className="progress__track"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={max}
        aria-valuenow={value}
        aria-label={label}
      >
        <div className="progress__bar" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

export function Tooltip({
  label,
  children,
}: {
  readonly label: string
  readonly children: ReactNode
}) {
  return (
    <span className="tooltip">
      {children}
      <span className="tooltip__bubble" role="tooltip">
        {label}
      </span>
    </span>
  )
}

export type { ButtonHTMLAttributes }
