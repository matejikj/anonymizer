import { useRef, useState } from 'react'
import { useAppStore } from '../../app/store.ts'
import { cs } from '../../i18n/cs.ts'
import {
  BundleCancelledError,
  BundleLifecycleError,
  cancelBundleJob,
  exportActiveMappingBundle,
  exportCorrelationMappingBundle,
  importMappingBundleFile,
} from './bundleController.ts'
import { MappingBundleExportDialog, MappingBundleImportDialog } from './MappingBundleDialogs.tsx'
import { forceResolveReturnLookupStep } from '../resolve-only/resolveReturnController.ts'
import { enterResolveOnly } from '../../app/sessionLifecycleCoordinator.ts'
import { Button } from '../../design-system/index.ts'

type DialogMode = 'none' | 'export' | 'import'

function bundleErrorMessage(err: unknown): string {
  if (err instanceof BundleLifecycleError) {
    if (err.code === 'bundle-empty') return cs.bundle.emptyMapping
    return err.message
  }
  if (err instanceof Error) return err.message
  return cs.bundle.failed
}

export function MappingBundleActions(props: {
  mode: 'text' | 'pcap' | 'correlation'
  disabled?: boolean
  showExport?: boolean
  showImport?: boolean
  exportTestId?: string
  /** `toolbar` = tertiary ghost action for text workspace; default keeps dashboard/menu chrome. */
  presentation?: 'default' | 'toolbar'
}) {
  const showExport = props.showExport !== false
  const showImport = props.showImport !== false
  const presentation = props.presentation ?? 'default'
  const [dialog, setDialog] = useState<DialogMode>('none')
  const [busy, setBusy] = useState(false)
  const [importFile, setImportFile] = useState<File | null>(null)
  const filePickerRef = useRef<HTMLInputElement>(null)
  const abortRef = useRef<AbortController | null>(null)

  const closeDialog = () => {
    if (busy) {
      abortRef.current?.abort()
      cancelBundleJob()
    }
    setDialog('none')
    setImportFile(null)
    setBusy(false)
  }

  const runExport = async () => {
    abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac
    setBusy(true)
    try {
      if (props.mode === 'correlation') {
        await exportCorrelationMappingBundle({ signal: ac.signal })
      } else {
        await exportActiveMappingBundle({ mode: props.mode, signal: ac.signal })
      }
      useAppStore.getState().setToast({ message: cs.bundle.exported })
      setDialog('none')
    } catch (err) {
      if (err instanceof BundleCancelledError) {
        useAppStore.getState().setToast({ message: cs.bundle.cancelled })
        return
      }
      useAppStore.getState().setToast({ message: bundleErrorMessage(err) })
    } finally {
      setBusy(false)
      abortRef.current = null
    }
  }

  const runImport = async () => {
    if (!importFile) return
    abortRef.current?.abort()
    const ac = new AbortController()
    abortRef.current = ac
    setBusy(true)
    try {
      const result = await importMappingBundleFile({ file: importFile, signal: ac.signal })
      enterResolveOnly({ mode: 'imported' })
      forceResolveReturnLookupStep()
      useAppStore.getState().setToast({
        message: cs.bundle.imported.replace('{n}', String(result.entryCount)),
      })
      setDialog('none')
      setImportFile(null)
    } catch (err) {
      if (err instanceof BundleCancelledError) {
        useAppStore.getState().setToast({ message: cs.bundle.cancelled })
        return
      }
      useAppStore.getState().setToast({ message: bundleErrorMessage(err) })
    } finally {
      setBusy(false)
      abortRef.current = null
    }
  }

  const exportLabel =
    presentation === 'toolbar' ? cs.bundle.exportToolbar : cs.bundle.exportShort

  return (
    <div
      className={
        presentation === 'toolbar'
          ? 'command-strip__bundle command-strip__bundle--toolbar'
          : 'command-strip__bundle'
      }
      data-testid="mapping-bundle-actions"
      data-presentation={presentation}
    >
      {showExport ? (
        <Button
          variant="ghost"
          data-testid={props.exportTestId ?? 'mapping-bundle-export-open'}
          disabled={props.disabled || busy}
          title={presentation === 'toolbar' ? cs.bundle.mapMenuHint : undefined}
          onClick={() => setDialog('export')}
        >
          {exportLabel}
        </Button>
      ) : null}
      {presentation === 'toolbar' || !showImport ? null : (
        <Button
          variant="ghost"
          data-testid="mapping-bundle-import-open"
          disabled={busy}
          onClick={() => {
            setImportFile(null)
            setDialog('import')
          }}
        >
          {cs.bundle.importAction}
        </Button>
      )}
      <input
        ref={filePickerRef}
        type="file"
        accept=".rnd-mapping-bundle.json,application/json"
        hidden
        aria-label={cs.bundle.importAction}
        onChange={(e) => {
          setImportFile(e.target.files?.[0] ?? null)
          e.target.value = ''
        }}
      />
      {dialog === 'export' ? (
        <MappingBundleExportDialog busy={busy} onCancel={closeDialog} onConfirm={() => void runExport()} />
      ) : null}
      {dialog === 'import' ? (
        <MappingBundleImportDialog
          busy={busy}
          fileName={importFile?.name ?? null}
          onCancel={closeDialog}
          onPickFile={() => filePickerRef.current?.click()}
          onConfirm={() => void runImport()}
        />
      ) : null}
    </div>
  )
}
