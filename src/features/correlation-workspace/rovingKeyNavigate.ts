/**
 * Roving tabindex keyboard helpers for listbox-style navigation (Stage 31).
 */

export function rovingKeyNavigate(
  event: { key: string; preventDefault: () => void },
  options: {
    readonly itemCount: number
    readonly activeIndex: number
    readonly onActivate: (index: number) => void
    readonly onSelect: (index: number) => void
  },
): void {
  const { itemCount, activeIndex, onActivate, onSelect } = options
  if (itemCount <= 0) return

  switch (event.key) {
    case 'ArrowDown':
    case 'ArrowRight':
      event.preventDefault()
      onActivate((activeIndex + 1) % itemCount)
      break
    case 'ArrowUp':
    case 'ArrowLeft':
      event.preventDefault()
      onActivate((activeIndex - 1 + itemCount) % itemCount)
      break
    case 'Home':
      event.preventDefault()
      onActivate(0)
      break
    case 'End':
      event.preventDefault()
      onActivate(itemCount - 1)
      break
    case 'Enter':
    case ' ':
      event.preventDefault()
      onSelect(activeIndex)
      break
    default:
      break
  }
}
