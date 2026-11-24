import type { ButtonHTMLAttributes, ReactNode } from 'react'

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Accessible name — required when children are decorative icons. */
  readonly label: string
  readonly children: ReactNode
  readonly tiny?: boolean
  readonly busy?: boolean
}

/**
 * Icon button — accessible name required; flat instrument chrome via `.btn--icon`.
 */
export function IconButton({
  label,
  children,
  tiny,
  busy,
  className,
  disabled,
  type = 'button',
  ...rest
}: IconButtonProps) {
  return (
    <button
      type={type}
      className={['btn', 'btn--ghost', 'btn--icon', tiny ? 'btn--tiny' : '', className]
        .filter(Boolean)
        .join(' ')}
      aria-label={label}
      title={label}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      data-control="icon-button"
      {...rest}
    >
      {children}
    </button>
  )
}
