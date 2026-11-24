import { SourceKind } from '../../domain/sourceArtifact.ts'
import { sourceKindShort } from '../../correlation/correlationReviewModel.ts'

export interface FileKindBadgeProps {
  readonly kind: typeof SourceKind.Text | typeof SourceKind.Pcap
  readonly className?: string
}

export function FileKindBadge({ kind, className }: FileKindBadgeProps) {
  const short = sourceKindShort(kind)
  const mod = kind === SourceKind.Pcap ? 'pcap' : 'text'
  return (
    <span className={`file-kind-badge file-kind-badge--${mod}${className ? ` ${className}` : ''}`} aria-hidden="true">
      {short}
    </span>
  )
}
