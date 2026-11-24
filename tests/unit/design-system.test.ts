import { describe, expect, it } from 'vitest'
import { Button } from '../../src/design-system/Button.tsx'
import { DataSurface, GlassPanel } from '../../src/design-system/Surfaces.tsx'
import { CommandBar, WorkspaceChrome } from '../../src/design-system/Patterns.tsx'
import { renderToStaticMarkup } from 'react-dom/server'
import { createElement } from 'react'

describe('Design-system components', () => {
  it('Button maps variants to stable classes', () => {
    const html = renderToStaticMarkup(
      createElement(Button, { variant: 'primary', busy: true }, 'Go'),
    )
    expect(html).toContain('btn--primary')
    expect(html).toContain('aria-busy="true"')
  })

  it('DataSurface never opts into glass class', () => {
    const html = renderToStaticMarkup(createElement(DataSurface, null, 'data'))
    expect(html).toContain('ds-data-surface')
    expect(html).not.toContain('ds-glass-panel')
    expect(html).not.toContain('surface-glass')
  })

  it('GlassPanel is the only glass surface helper', () => {
    const html = renderToStaticMarkup(createElement(GlassPanel, null, 'glass'))
    expect(html).toContain('ds-glass-panel')
  })

  it('CommandBar orders context before primary', () => {
    const html = renderToStaticMarkup(
      createElement(CommandBar, {
        context: createElement('span', null, 'ctx'),
        primary: createElement('span', null, 'pri'),
        testId: 'cb',
      }),
    )
    expect(html.indexOf('ctx')).toBeLessThan(html.indexOf('pri'))
    expect(html).toContain('ds-command-bar')
  })

  it('WorkspaceChrome uses shared slot order and embedded class', () => {
    const standalone = renderToStaticMarkup(
      createElement(WorkspaceChrome, {
        context: createElement('span', null, 'file'),
        tools: createElement('span', null, 'nav'),
        status: createElement('span', null, 'stat'),
        primary: createElement('span', null, 'export'),
        testId: 'wc-standalone',
        mode: 'standalone',
      }),
    )
    expect(standalone).toContain('workspace-chrome')
    expect(standalone).not.toContain('workspace-chrome--embedded')
    expect(standalone.indexOf('file')).toBeLessThan(standalone.indexOf('nav'))
    expect(standalone.indexOf('nav')).toBeLessThan(standalone.indexOf('stat'))
    expect(standalone.indexOf('stat')).toBeLessThan(standalone.indexOf('export'))
    expect(standalone).toContain('data-mode="standalone"')

    const embedded = renderToStaticMarkup(
      createElement(WorkspaceChrome, {
        embedded: true,
        tools: createElement('span', null, 'tools-only'),
        testId: 'wc-embedded',
        mode: 'embedded',
      }),
    )
    expect(embedded).toContain('workspace-chrome--embedded')
    expect(embedded).toContain('tools-only')
    expect(embedded).not.toContain('ds-command-bar__primary')
    expect(embedded).toContain('data-mode="embedded"')
  })
})
