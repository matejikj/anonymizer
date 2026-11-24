/** Inline SVG icons — Clear Glass Operations outline set (Stage 7). */

import type { ReactNode } from 'react'

export interface IconProps {
  readonly className?: string
  /** Pixel size — defaults to 18 (md). Use 16 / 18 / 20. */
  readonly size?: 16 | 18 | 20
}

const STROKE = 1.75

function iconClass(className: string | undefined, size: 16 | 18 | 20): string {
  const sizeClass = size === 16 ? 'ui-icon ui-icon--sm' : size === 20 ? 'ui-icon ui-icon--lg' : 'ui-icon'
  return className ? `${sizeClass} ${className}` : sizeClass
}

function Svg({
  className,
  size = 18,
  children,
}: IconProps & { readonly children: ReactNode }) {
  return (
    <svg
      className={iconClass(className, size)}
      width={size}
      height={size}
      viewBox="0 0 18 18"
      fill="none"
      aria-hidden="true"
    >
      {children}
    </svg>
  )
}

export function IconCheck({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M3.5 9.2 7.2 12.8 14.5 4.8"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </Svg>
  )
}

export function IconX({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M4.5 4.5 13.5 13.5M13.5 4.5 4.5 13.5"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
      />
    </Svg>
  )
}

/** Alias for close / dismiss actions. */
export const IconClose = IconX

export function IconWarning({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M9 2.8 15.7 14.5H2.3L9 2.8Z"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinejoin="round"
      />
      <path d="M9 7.2v3.2M9 12.6h.01" stroke="currentColor" strokeWidth={STROKE} strokeLinecap="round" />
    </Svg>
  )
}

export function IconDot({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="9" cy="9" r="3.5" fill="currentColor" />
    </Svg>
  )
}

export function IconCircle({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="9" cy="9" r="5" stroke="currentColor" strokeWidth={STROKE} />
    </Svg>
  )
}

export function IconHelp({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="9" cy="9" r="6.25" stroke="currentColor" strokeWidth={STROKE} />
      <path
        d="M7.1 7.1a1.9 1.9 0 0 1 3.7.9c0 1.2-1.85 1.7-1.85 2.7"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
      />
      <path d="M9 13.2h.01" stroke="currentColor" strokeWidth={STROKE} strokeLinecap="round" />
    </Svg>
  )
}

/** Local-only / privacy signal for header menubar. */
export function IconLock({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <rect
        x="4.5"
        y="8"
        width="9"
        height="7"
        rx="1.25"
        stroke="currentColor"
        strokeWidth={STROKE}
      />
      <path
        d="M6.5 8V6.2a2.5 2.5 0 0 1 5 0V8"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
      />
    </Svg>
  )
}

/** Compact add control for set chrome. */
export function IconPlus({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M9 4.5v9M4.5 9h9"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
      />
    </Svg>
  )
}

export function IconChevronDown({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M4.5 7 9 11.5 13.5 7"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </Svg>
  )
}

export function IconChevronRight({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M7 4.5 11.5 9 7 13.5"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </Svg>
  )
}

export function IconExport({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M9 11.5V3.5M6 6l3-3 3 3"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M3.5 10.5v3a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-3"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </Svg>
  )
}

export function IconInfo({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="9" cy="9" r="6.25" stroke="currentColor" strokeWidth={STROKE} />
      <path d="M9 8.2v4.2M9 5.8h.01" stroke="currentColor" strokeWidth={STROKE} strokeLinecap="round" />
    </Svg>
  )
}

export function IconFile({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M5 2.5h5.5L14.5 6.5V15a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1Z"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinejoin="round"
      />
      <path d="M10.5 2.5V6.5H14.5" stroke="currentColor" strokeWidth={STROKE} strokeLinejoin="round" />
    </Svg>
  )
}

export function IconBook({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M9 5.4C7.6 4.3 5.7 3.7 3.6 3.7c-.4 0-.7.3-.7.7v8.4c0 .4.3.7.7.7 2 0 3.8.6 5.1 1.7"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M9 5.4c1.4-1.1 3.3-1.7 5.4-1.7.4 0 .7.3.7.7v8.4c0 .4-.3.7-.7.7-2 0-3.8.6-5.1 1.7"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path d="M9 5.4v9.5" stroke="currentColor" strokeWidth={STROKE} strokeLinecap="round" />
    </Svg>
  )
}

export function IconSearch({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="8" cy="8" r="4.25" stroke="currentColor" strokeWidth={STROKE} />
      <path d="M11.2 11.2 15 15" stroke="currentColor" strokeWidth={STROKE} strokeLinecap="round" />
    </Svg>
  )
}

export function IconMore({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="4.5" cy="9" r="1.15" fill="currentColor" />
      <circle cx="9" cy="9" r="1.15" fill="currentColor" />
      <circle cx="13.5" cy="9" r="1.15" fill="currentColor" />
    </Svg>
  )
}

export function IconSettings({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="9" cy="9" r="2.25" stroke="currentColor" strokeWidth={STROKE} />
      <path
        d="M9 2.5v1.4M9 14.1v1.4M2.5 9h1.4M14.1 9h1.4M4.2 4.2l1 1M12.8 12.8l1 1M13.8 4.2l-1 1M5.2 12.8l-1 1"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
      />
    </Svg>
  )
}

export function IconWarn({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path
        d="M9 2.8 15.2 14.5H2.8L9 2.8Z"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinejoin="round"
      />
      <path d="M9 7.2v3.4M9 12.6h.01" stroke="currentColor" strokeWidth={STROKE} strokeLinecap="round" />
    </Svg>
  )
}

export function IconError({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="9" cy="9" r="6.25" stroke="currentColor" strokeWidth={STROKE} />
      <path d="M6.5 6.5 11.5 11.5M11.5 6.5 6.5 11.5" stroke="currentColor" strokeWidth={STROKE} strokeLinecap="round" />
    </Svg>
  )
}

export function IconHelpMark({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <circle cx="9" cy="9" r="6.25" stroke="currentColor" strokeWidth={STROKE} />
      <path
        d="M7.2 7.1a1.9 1.9 0 0 1 3.5 1c0 1.2-1.7 1.5-1.7 2.6M9 13h.01"
        stroke="currentColor"
        strokeWidth={STROKE}
        strokeLinecap="round"
      />
    </Svg>
  )
}

export function IconArrow({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M4 9h9.5M10 5.5 13.5 9 10 12.5" stroke="currentColor" strokeWidth={STROKE} strokeLinecap="round" strokeLinejoin="round" />
    </Svg>
  )
}

export function IconDiamond({ className, size }: IconProps) {
  return (
    <Svg className={className} size={size}>
      <path d="M9 3.2 14.8 9 9 14.8 3.2 9 9 3.2Z" stroke="currentColor" strokeWidth={STROKE} strokeLinejoin="round" />
    </Svg>
  )
}
