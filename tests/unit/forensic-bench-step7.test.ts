import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = process.cwd()

function read(rel: string): string {
  return readFileSync(join(root, rel), 'utf8')
}

describe('FORENSIC_BENCH step 7 — lab progress', () => {
  const splash = read('src/design-system/ProgressSplash.tsx')
  const css = read('src/styles/progress-splash.css')

  it('uses page-title (not display) and omits hero visual', () => {
    expect(splash).toMatch(/progress-splash__title type-page-title/)
    expect(splash).not.toMatch(/type-display/)
    expect(splash).not.toMatch(/progress-splash__visual/)
    expect(splash).not.toMatch(/progress-splash__pulse/)
    expect(splash).not.toMatch(/progress-splash__orbit/)
  })

  it('keeps eyebrow/tip as meta and cancel available', () => {
    expect(splash).toMatch(/progress-splash__eyebrow type-meta/)
    expect(splash).toMatch(/progress-splash__tip type-meta/)
    expect(splash).toMatch(/data-testid=\{cancelTestId\}/)
    expect(splash).toMatch(/variant="ghost"/)
  })

  it('styles progress as opaque lab panel without glass / brand spin', () => {
    expect(css).toMatch(/backdrop-filter:\s*none/)
    expect(css).toMatch(/box-shadow:\s*none/)
    expect(css).not.toMatch(/progress-splash-pulse/)
    expect(css).not.toMatch(/progress-splash-spin/)
    expect(css).not.toMatch(/progress-splash-shimmer/)
    expect(css).toMatch(/prefers-reduced-motion/)
  })

  it('leaves no type-display in product UI sources', () => {
    expect(splash).not.toMatch(/type-display/)
    expect(read('src/features/import-log/TextProgressView.tsx')).not.toMatch(/type-display/)
    expect(read('src/pcap/ui/PcapProgressView.tsx')).not.toMatch(/type-display/)
    expect(read('src/features/correlation-workspace/CorrelationProgressView.tsx')).not.toMatch(
      /type-display/,
    )
  })
})
