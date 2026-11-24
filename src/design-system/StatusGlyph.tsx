/** Status verdict icons — Clear Glass Operations (Stage 9). No text glyphs. */

import type { ReactNode } from 'react'
import { IconCheck, IconWarn, IconError, IconHelpMark, IconDiamond } from '../components/ui/icons.tsx'

export type StatusGlyphKind = 'ok' | 'warn' | 'blocked' | 'unknown' | 'sanitizer'

const LABEL: Record<StatusGlyphKind, string> = {
  ok: 'V pořádku',
  warn: 'Vyžaduje pozornost',
  blocked: 'Blokováno',
  unknown: 'Neznámý stav',
  sanitizer: 'Sanitizer',
}

export function StatusGlyph({
  kind,
  label,
  className,
}: {
  readonly kind: StatusGlyphKind
  readonly label?: string
  readonly className?: string
}): ReactNode {
  const accessible = label ?? LABEL[kind]
  const icon =
    kind === 'ok' ? (
      <IconCheck size={16} />
    ) : kind === 'warn' ? (
      <IconWarn size={16} />
    ) : kind === 'blocked' ? (
      <IconError size={16} />
    ) : kind === 'sanitizer' ? (
      <IconDiamond size={16} />
    ) : (
      <IconHelpMark size={16} />
    )

  return (
    <span className={['status-glyph', `status-glyph--${kind}`, className].filter(Boolean).join(' ')} title={accessible}>
      <span className="visually-hidden">{accessible}</span>
      <span aria-hidden="true">{icon}</span>
    </span>
  )
}
