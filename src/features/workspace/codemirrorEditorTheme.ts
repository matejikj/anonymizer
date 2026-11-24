import { EditorView } from '@codemirror/view'

/**
 * Shared data-view theme for CodeMirror — Forensic Bench selection rail.
 * Opaque editor surface; active occurrence = 2px left rail + subtle tint.
 */
export const logEditorTheme = EditorView.theme({
  '&': {
    height: '100%',
    fontSize: 'var(--text-mono)',
    background: 'var(--surface-data)',
    color: 'var(--text-primary)',
  },
  '.cm-scroller': {
    fontFamily: 'var(--font-mono)',
    lineHeight: 'var(--line)',
  },
  '.cm-content': {
    caretColor: 'var(--color-accent)',
  },
  '.cm-gutters': {
    background: 'var(--data-gutter-bg, var(--surface-raised))',
    color: 'var(--text-muted)',
    borderRight: '1px solid var(--border-default, var(--color-border))',
  },
  '.cm-activeLineGutter': {
    background: 'var(--data-selection-bg)',
  },
  '.cm-activeLine': {
    background: 'var(--data-current-line-bg)',
    boxShadow: 'var(--selection-rail)',
  },
  '.cm-anon-replacement': {
    background: 'var(--data-anon-bg)',
    color: 'var(--data-anon-ink)',
    fontWeight: 'var(--weight-semibold)',
    outline: '1px solid var(--data-anon-outline)',
    borderRadius: '2px',
  },
  '.cm-original-match': {
    background: 'var(--data-original-bg)',
    color: 'var(--data-original-ink)',
    fontWeight: 'var(--weight-semibold)',
    boxShadow: 'none',
    outline: '1px solid var(--data-original-outline)',
    borderRadius: '2px',
  },
  '.cm-sync-line': {
    background: 'var(--data-selection-bg)',
    boxShadow: 'var(--selection-rail)',
  },
  '.cm-sync-match': {
    background: 'color-mix(in srgb, var(--color-accent) 22%, var(--surface-data))',
    color: 'var(--color-accent)',
    fontWeight: 'var(--weight-semibold)',
    boxShadow: 'var(--selection-rail)',
    outline: '1px solid color-mix(in srgb, var(--color-accent) 55%, transparent)',
    borderRadius: '2px',
    animation: 'none',
  },
  '&.cm-focused': {
    outline: 'none',
    boxShadow: 'inset 0 0 0 1px var(--border-interactive)',
  },
})
