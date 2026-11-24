import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react'

export interface FieldProps {
  readonly id: string
  readonly label: string
  readonly hint?: string
  readonly error?: string
  readonly children: ReactNode
  readonly className?: string
}

export function Field({ id, label, hint, error, children, className }: FieldProps) {
  return (
    <div className={['field', className].filter(Boolean).join(' ')} data-state={error ? 'error' : undefined}>
      <label className="field__label" htmlFor={id}>
        {label}
      </label>
      {children}
      {error ? (
        <p className="field__error" role="alert" id={`${id}-error`}>
          {error}
        </p>
      ) : hint ? (
        <p className="field__hint" id={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
    </div>
  )
}

export function TextInput({
  id,
  label,
  hint,
  error,
  className,
  ...rest
}: Omit<FieldProps, 'children'> & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <Field id={id} label={label} hint={hint} error={error}>
      <input
        id={id}
        className={['field__control', className].filter(Boolean).join(' ')}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
        {...rest}
      />
    </Field>
  )
}

export function SearchField({
  id,
  label,
  className,
  ...rest
}: { readonly id: string; readonly label: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div className={['search-field', className].filter(Boolean).join(' ')}>
      <label className="visually-hidden" htmlFor={id}>
        {label}
      </label>
      <input id={id} type="search" className="search-field__input" {...rest} />
    </div>
  )
}

export function SelectField({
  id,
  label,
  hint,
  error,
  children,
  className,
  ...rest
}: Omit<FieldProps, 'children'> &
  SelectHTMLAttributes<HTMLSelectElement> & { readonly children: ReactNode }) {
  return (
    <Field id={id} label={label} hint={hint} error={error}>
      <select
        id={id}
        className={['field__control', className].filter(Boolean).join(' ')}
        aria-invalid={error ? true : undefined}
        {...rest}
      >
        {children}
      </select>
    </Field>
  )
}

export function TextareaField({
  id,
  label,
  hint,
  error,
  className,
  ...rest
}: Omit<FieldProps, 'children'> & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <Field id={id} label={label} hint={hint} error={error}>
      <textarea
        id={id}
        className={['field__control', className].filter(Boolean).join(' ')}
        aria-invalid={error ? true : undefined}
        {...rest}
      />
    </Field>
  )
}

export function Checkbox({
  id,
  label,
  className,
  ...rest
}: { readonly id: string; readonly label: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className={['checkbox', className].filter(Boolean).join(' ')} htmlFor={id}>
      <input id={id} type="checkbox" {...rest} />
      <span>{label}</span>
    </label>
  )
}

export function Switch({
  id,
  label,
  className,
  ...rest
}: { readonly id: string; readonly label: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className={['switch', className].filter(Boolean).join(' ')} htmlFor={id}>
      <input id={id} type="checkbox" role="switch" {...rest} />
      <span>{label}</span>
    </label>
  )
}
