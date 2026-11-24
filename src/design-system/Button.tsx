import type { ButtonHTMLAttributes, ReactNode } from 'react'

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'quiet' | 'destructive' | 'link' | 'danger'
export type ButtonSize = 'default' | 'lg' | 'tiny'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  readonly variant?: ButtonVariant
  readonly size?: ButtonSize
  readonly busy?: boolean
  readonly children?: ReactNode
}

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary: 'btn--primary',
  secondary: 'btn--secondary',
  ghost: 'btn--ghost',
  quiet: 'btn--quiet',
  destructive: 'btn--destructive',
  link: 'btn--link',
  danger: 'btn--danger',
}

const SIZE_CLASS: Record<ButtonSize, string> = {
  default: '',
  lg: 'btn--lg',
  tiny: 'btn--tiny',
}

export function Button({
  variant = 'secondary',
  size = 'default',
  busy = false,
  className,
  disabled,
  children,
  type = 'button',
  ...rest
}: ButtonProps) {
  const classes = [
    'btn',
    VARIANT_CLASS[variant],
    SIZE_CLASS[size],
    className,
  ]
    .filter(Boolean)
    .join(' ')

  return (
    <button
      type={type}
      className={classes}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      data-state={busy ? 'busy' : disabled ? 'disabled' : undefined}
      {...rest}
    >
      {children}
    </button>
  )
}
