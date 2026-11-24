import { cs } from '../../i18n/cs.ts'
import { useAppStore } from '../../app/store.ts'
import { Button } from '../../design-system/index.ts'

/** Toggle resolve lookup panel in active text/PCAP session (Stage 22). */
export function ResolveOpenButton({ compact = false }: { readonly compact?: boolean }) {
  const open = useAppStore((s) => s.resolvePanelOpen)
  const setOpen = useAppStore((s) => s.setResolvePanelOpen)

  return (
    <Button
      variant="ghost"
      size={compact ? 'tiny' : 'default'}
      data-testid="resolve-open-toggle"
      aria-pressed={open}
      onClick={() => setOpen(!open)}
    >
      {open ? cs.resolve.close : compact ? cs.resolve.openShort : cs.resolve.open}
    </Button>
  )
}
