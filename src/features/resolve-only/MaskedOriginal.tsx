/**
 * Masked original display — default hidden; explicit reveal / copy (Stage 30).
 */

import { useState } from 'react'
import { cs } from '../../i18n/cs.ts'
import { Button } from '../../design-system/index.ts'

function maskValue(value: string): string {
  if (value.length <= 4) return '••••'
  return `${value.slice(0, 2)}${'•'.repeat(Math.min(10, value.length - 4))}${value.slice(-2)}`
}

export function MaskedOriginal(props: {
  value: string
  testId?: string
}) {
  const [revealed, setRevealed] = useState(false)
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      // parent may surface clipboard errors; keep silent here
    }
  }

  return (
    <span className="resolve-masked" data-testid={props.testId ?? 'resolve-masked-original'}>
      <code
        className={`resolve-masked__value${revealed ? ' is-revealed' : ''}`}
        data-testid="resolve-masked-value"
      >
        {revealed ? props.value : maskValue(props.value)}
      </code>
      <span className="resolve-masked__actions">
        <Button
          variant="ghost"
          size="tiny"
          data-testid="resolve-reveal-original"
          aria-pressed={revealed}
          onClick={() => setRevealed((v) => !v)}
        >
          {revealed ? cs.resolveReturn.hideOriginal : cs.resolveReturn.revealOriginal}
        </Button>
        <Button
          variant="ghost"
          size="tiny"
          data-testid="resolve-copy-original"
          onClick={() => void copy()}
        >
          {copied ? cs.resolveReturn.copied : cs.resolveReturn.copyOriginal}
        </Button>
      </span>
    </span>
  )
}
