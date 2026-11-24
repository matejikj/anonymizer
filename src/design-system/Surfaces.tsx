import type { HTMLAttributes, ReactNode } from 'react'

type DivProps = HTMLAttributes<HTMLDivElement>

export function DataSurface({ className, children, ...rest }: DivProps & { readonly children?: ReactNode }) {
  return (
    <div className={['ds-data-surface', 'surface-data', className].filter(Boolean).join(' ')} {...rest}>
      {children}
    </div>
  )
}

export function RaisedPanel({ className, children, ...rest }: DivProps & { readonly children?: ReactNode }) {
  return (
    <div className={['ds-raised-panel', 'surface-raised', className].filter(Boolean).join(' ')} {...rest}>
      {children}
    </div>
  )
}

/** Glass chrome only — never wrap editors / grids. */
export function GlassPanel({ className, children, ...rest }: DivProps & { readonly children?: ReactNode }) {
  return (
    <div className={['ds-glass-panel', 'surface-glass', className].filter(Boolean).join(' ')} {...rest}>
      {children}
    </div>
  )
}

export function Card({ className, children, ...rest }: DivProps & { readonly children?: ReactNode }) {
  return (
    <div className={['ds-card', className].filter(Boolean).join(' ')} {...rest}>
      {children}
    </div>
  )
}

export function Inspector({
  className,
  children,
  label,
  ...rest
}: DivProps & { readonly children?: ReactNode; readonly label: string }) {
  return (
    <aside
      className={['ds-inspector', className].filter(Boolean).join(' ')}
      aria-label={label}
      {...rest}
    >
      {children}
    </aside>
  )
}
