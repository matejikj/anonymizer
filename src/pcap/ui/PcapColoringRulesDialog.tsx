import { useMemo, useState, useEffect } from 'react'
import { cs } from '../../i18n/cs.ts'
import { usePcapStore } from './pcapStore.ts'
import { AccessibleModal, Button } from '../../design-system/index.ts'
import type { PcapColoringRule } from '../coloring/types'
import { compileColoringRules, sanitizeColorPair, validateColorPair, meetsWcagAa } from '../coloring'
import { createDefaultColoringRules } from '../coloring/defaultRules'

export function PcapColoringRulesDialog() {
  const open = usePcapStore((s) => s.coloringRulesDialogOpen)
  const setOpen = usePcapStore((s) => s.setColoringRulesDialogOpen)
  const coloringRules = usePcapStore((s) => s.coloringRules)
  const setColoringRules = usePcapStore((s) => s.setColoringRules)
  const resetDefaults = usePcapStore((s) => s.resetColoringRulesToDefaults)

  const editableRules = useMemo(
    () => coloringRules.filter((r) => r.source !== 'temporary-conversation'),
    [coloringRules],
  )

  const [draft, setDraft] = useState<readonly PcapColoringRule[]>(editableRules)
  const [editingId, setEditingId] = useState<string | null>(null)

  useEffect(() => {
    if (open) setDraft(editableRules)
  }, [open, editableRules])

  if (!open) return null

  const compiled = compileColoringRules(draft)
  const defaults = createDefaultColoringRules()

  const syncDraft = (rules: readonly PcapColoringRule[]) => {
    setDraft(rules)
    setColoringRules(rules.filter((r) => r.source === 'user'))
  }

  const onClose = () => {
    setEditingId(null)
    setOpen(false)
  }

  const onReset = () => {
    resetDefaults()
    setDraft(defaults)
    setEditingId(null)
  }

  const moveRule = (id: string, direction: -1 | 1) => {
    const sorted = [...draft].sort((a, b) => a.priority - b.priority)
    const idx = sorted.findIndex((r) => r.id === id)
    if (idx < 0) return
    const swapIdx = idx + direction
    if (swapIdx < 0 || swapIdx >= sorted.length) return
    const a = sorted[idx]!
    const b = sorted[swapIdx]!
    const next = sorted.map((r) => {
      if (r.id === a.id) return { ...r, priority: b.priority }
      if (r.id === b.id) return { ...r, priority: a.priority }
      return r
    })
    syncDraft(next)
  }

  const toggleEnabled = (id: string) => {
    syncDraft(
      draft.map((r) =>
        r.id === id
          ? { ...r, enabled: !r.enabled, source: r.source === 'default' ? 'user' : r.source }
          : r,
      ),
    )
  }

  const updateRule = (id: string, patch: Partial<PcapColoringRule>) => {
    syncDraft(
      draft.map((r) => {
        if (r.id !== id) return r
        const next = { ...r, ...patch, source: r.source === 'default' ? 'user' as const : r.source }
        if (patch.light) next.light = sanitizeColorPair({ ...r.light, ...patch.light })
        if (patch.dark) next.dark = sanitizeColorPair({ ...r.dark, ...patch.dark })
        return next
      }),
    )
  }

  const duplicateRule = (rule: PcapColoringRule) => {
    const copy: PcapColoringRule = {
      ...rule,
      id: `user-${Date.now()}`,
      name: `${rule.name} (copy)`,
      source: 'user',
      priority: rule.priority + 1,
      light: { ...rule.light },
      dark: { ...rule.dark },
    }
    syncDraft([...draft, copy])
    setEditingId(copy.id)
  }

  const deleteRule = (id: string) => {
    syncDraft(draft.filter((r) => r.id !== id))
    if (editingId === id) setEditingId(null)
  }

  const addRule = () => {
    const rule: PcapColoringRule = {
      id: `user-${Date.now()}`,
      name: cs.pcap.coloring.newRuleName,
      enabled: true,
      priority: (draft.reduce((m, r) => Math.max(m, r.priority), 0) || 0) + 10,
      filter: 'tcp',
      light: { foreground: '#111827', background: '#f3f4f6' },
      dark: { foreground: '#f9fafb', background: '#1f2937' },
      source: 'user',
    }
    syncDraft([...draft, rule])
    setEditingId(rule.id)
  }

  const sorted = [...draft].sort((a, b) => a.priority - b.priority)

  return (
    <AccessibleModal
      open
      onClose={onClose}
      titleId="pcap-coloring-rules-title"
      title={cs.pcap.coloring.dialogTitle}
      testId="pcap-coloring-rules-dialog"
      actions={
        <>
          <Button variant="ghost" onClick={onReset} data-testid="pcap-coloring-reset">
            {cs.pcap.coloring.resetDefaults}
          </Button>
          <Button variant="primary" onClick={onClose} data-testid="pcap-coloring-close">
            {cs.pcap.coloring.close}
          </Button>
        </>
      }
    >
      <p className="pcap-coloring-dialog__hint">{cs.pcap.coloring.firstMatchHint}</p>
      <p className="pcap-coloring-dialog__hint pcap-coloring-dialog__hint--secondary" role="note">
        {cs.pcap.coloring.overlapHint}
      </p>
      <div className="pcap-coloring-dialog__toolbar">
        <Button variant="secondary" onClick={addRule} data-testid="pcap-coloring-add">
          {cs.pcap.coloring.addRule}
        </Button>
      </div>
      <ol className="pcap-coloring-dialog__list" data-testid="pcap-coloring-rule-list">
        {sorted.map((rule, index) => {
          const compiledRule = compiled.rules.find((c) => c.id === rule.id)
          const invalid = compiledRule?.error
          const lightOk = meetsWcagAa(rule.light.foreground, rule.light.background)
          const darkOk = meetsWcagAa(rule.dark.foreground, rule.dark.background)
          const isEditing = editingId === rule.id
          return (
            <li
              key={rule.id}
              className={`pcap-coloring-dialog__item${!rule.enabled ? ' is-disabled' : ''}${invalid ? ' is-invalid' : ''}`}
              data-testid={`pcap-coloring-rule-${rule.id}`}
              draggable
              onDragOver={(e) => e.preventDefault()}
              onDragStart={(e) => {
                setEditingId(null)
                e.dataTransfer.setData('text/plain', String(index))
                e.dataTransfer.effectAllowed = 'move'
              }}
              onDrop={(e) => {
                e.preventDefault()
                const from = Number.parseInt(e.dataTransfer.getData('text/plain'), 10)
                if (!Number.isFinite(from) || from === index) return
                const next = [...sorted]
                const [moved] = next.splice(from, 1)
                if (!moved) return
                next.splice(index, 0, moved)
                syncDraft(
                  next.map((r, i) => ({
                    ...r,
                    priority: (i + 1) * 10,
                    source: r.source === 'default' ? 'user' : r.source,
                  })),
                )
              }}
            >
              <div className="pcap-coloring-dialog__item-head">
                <span
                  className="pcap-coloring-dialog__drag"
                  title={cs.pcap.coloring.dragHandle}
                  aria-hidden
                >
                  ⋮⋮
                </span>
                <label className="pcap-coloring-dialog__enable">
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    onChange={() => toggleEnabled(rule.id)}
                  />
                </label>
                <span
                  className="pcap-coloring-dialog__swatch"
                  style={{
                    ['--swatch-fg' as string]: rule.light.foreground,
                    ['--swatch-bg' as string]: rule.light.background,
                  }}
                  aria-hidden
                />
                <button
                  type="button"
                  className="pcap-coloring-dialog__name"
                  onClick={() => setEditingId(isEditing ? null : rule.id)}
                >
                  {rule.name}
                  {rule.source === 'default' ? ` (${cs.pcap.coloring.defaultBadge})` : ''}
                </button>
                <code className="pcap-coloring-dialog__filter">{rule.filter}</code>
                <div className="pcap-coloring-dialog__actions">
                  <Button variant="ghost" onClick={() => moveRule(rule.id, -1)} disabled={index === 0}>
                    ↑
                  </Button>
                  <Button variant="ghost" onClick={() => moveRule(rule.id, 1)} disabled={index === sorted.length - 1}>
                    ↓
                  </Button>
                  <Button variant="ghost" onClick={() => duplicateRule(rule)}>{cs.pcap.coloring.duplicate}</Button>
                  {rule.source === 'user' ? (
                    <Button variant="ghost" onClick={() => deleteRule(rule.id)}>{cs.pcap.coloring.delete}</Button>
                  ) : null}
                </div>
              </div>
              {invalid ? (
                <p className="pcap-coloring-dialog__error" role="alert">
                  {cs.pcap.coloring.invalidFilter.replace('{message}', invalid.message)}
                </p>
              ) : null}
              {!lightOk || !darkOk ? (
                <p className="pcap-coloring-dialog__warn" role="status">
                  {cs.pcap.coloring.lowContrast}
                </p>
              ) : null}
              {isEditing ? (
                <RuleEditor rule={rule} onChange={(patch) => updateRule(rule.id, patch)} />
              ) : null}
            </li>
          )
        })}
      </ol>
    </AccessibleModal>
  )
}

function RuleEditor({
  rule,
  onChange,
}: {
  rule: PcapColoringRule
  onChange: (patch: Partial<PcapColoringRule>) => void
}) {
  const lightIssue = validateColorPair(rule.light)
  const darkIssue = validateColorPair(rule.dark)
  return (
    <div className="pcap-coloring-dialog__editor">
      <label>
        {cs.pcap.coloring.fieldName}
        <input
          type="text"
          value={rule.name}
          maxLength={128}
          onChange={(e) => onChange({ name: e.target.value })}
        />
      </label>
      <label>
        {cs.pcap.coloring.fieldFilter}
        <input
          type="text"
          value={rule.filter}
          onChange={(e) => onChange({ filter: e.target.value })}
        />
      </label>
      <div className="pcap-coloring-dialog__colors">
        <fieldset>
          <legend>{cs.pcap.coloring.lightTheme}</legend>
          <label>
            FG
            <input type="color" value={rule.light.foreground} onChange={(e) => onChange({ light: { ...rule.light, foreground: e.target.value } })} />
          </label>
          <label>
            BG
            <input type="color" value={rule.light.background} onChange={(e) => onChange({ light: { ...rule.light, background: e.target.value } })} />
          </label>
          {lightIssue ? <span className="pcap-coloring-dialog__warn">{lightIssue}</span> : null}
        </fieldset>
        <fieldset>
          <legend>{cs.pcap.coloring.darkTheme}</legend>
          <label>
            FG
            <input type="color" value={rule.dark.foreground} onChange={(e) => onChange({ dark: { ...rule.dark, foreground: e.target.value } })} />
          </label>
          <label>
            BG
            <input type="color" value={rule.dark.background} onChange={(e) => onChange({ dark: { ...rule.dark, background: e.target.value } })} />
          </label>
          {darkIssue ? <span className="pcap-coloring-dialog__warn">{darkIssue}</span> : null}
        </fieldset>
      </div>
    </div>
  )
}
