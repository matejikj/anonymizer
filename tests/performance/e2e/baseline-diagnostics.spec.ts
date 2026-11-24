import { closeTextOutcomeDialog } from '../../e2e/helpers/textOutcome.ts'
import { test, expect } from '@playwright/test'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { generateMicroText } from '../maximumFixtureGenerators.ts'

const here = path.dirname(fileURLToPath(import.meta.url))
const resultsDir = path.resolve(here, '../results')

test.describe('Baseline — browser perf diagnostics', () => {
  test('records TTFP, TTI and long tasks on import', async ({ page }, testInfo) => {
    test.setTimeout(10 * 60_000)

    await page.addInitScript(() => {
      // Minimal inline hook — full module runs in Node baseline bench.
      const phases: Array<{ name: string; startMs: number; endMs?: number }> = []
      const origin = performance.now()
      let ttfp: number | undefined
      let tti: number | undefined
      let longTaskCount = 0
      let longTaskMaxMs = 0
      let copiedBytes = 0

      const hook = {
        markPhase(name: string) {
          phases.push({ name, startMs: performance.now() - origin })
        },
        endPhase(name: string) {
          const p = [...phases].reverse().find((x) => x.name === name && x.endMs === undefined)
          if (p) p.endMs = performance.now() - origin
        },
        recordFirstProgress() {
          if (ttfp === undefined) ttfp = performance.now() - origin
        },
        recordInteractive() {
          if (tti === undefined) tti = performance.now() - origin
        },
        recordCopy(n: number) {
          copiedBytes += n
        },
        recordLongTask(ms: number) {
          longTaskCount++
          longTaskMaxMs = Math.max(longTaskMaxMs, ms)
        },
        snapshot() {
          return { phases, timeToFirstProgressMs: ttfp, timeToInteractiveMs: tti, longTaskCount, longTaskMaxMs, copiedBytes }
        },
      }

      ;(globalThis as typeof globalThis & { __rndLogAnonymizerPerfDiagnostics?: typeof hook }).__rndLogAnonymizerPerfDiagnostics =
        hook

      try {
        const obs = new PerformanceObserver((list) => {
          for (const e of list.getEntries()) hook.recordLongTask(e.duration)
        })
        obs.observe({ type: 'longtask', buffered: true })
      } catch {
        /* unsupported */
      }
    })

    const fixture = generateMicroText(512 * 1024, 'lf')
    const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'rnd-baseline-ui-'))
    const filePath = path.join(dir, 'baseline-micro.log')
    await fs.promises.writeFile(filePath, fixture.text, 'utf8')

    await page.goto('/')
    const t0 = Date.now()

    await page.getByTestId('file-input').setInputFiles(filePath)

    await page.waitForFunction(() => {
      const hook = (globalThis as typeof globalThis & {
        __rndLogAnonymizerPerfDiagnostics?: { recordFirstProgress(): void }
      }).__rndLogAnonymizerPerfDiagnostics
      hook?.recordFirstProgress()
      return document.querySelector('[data-testid="workspace"]') !== null
    }, { timeout: 120_000 })

    await expect(page.getByTestId('export-bar')).toBeVisible()
    await closeTextOutcomeDialog(page)

    await page.evaluate(() => {
      const hook = (globalThis as typeof globalThis & {
        __rndLogAnonymizerPerfDiagnostics?: { recordInteractive(): void }
      }).__rndLogAnonymizerPerfDiagnostics
      hook?.recordInteractive()
    })

    const wallMs = Date.now() - t0
    const diag = await page.evaluate(() => {
      const hook = (globalThis as typeof globalThis & {
        __rndLogAnonymizerPerfDiagnostics?: { snapshot(): unknown }
      }).__rndLogAnonymizerPerfDiagnostics
      return hook?.snapshot() ?? null
    })

    const row = {
      browser: testInfo.project.name,
      inputBytes: fixture.byteLength,
      inputMiB: fixture.byteLength / (1024 * 1024),
      wallMs,
      diagnostics: diag,
    }

    fs.mkdirSync(resultsDir, { recursive: true })
    fs.writeFileSync(
      path.join(resultsDir, `baseline-ui-${testInfo.project.name}.json`),
      JSON.stringify(row, null, 2),
    )

    expect(wallMs).toBeLessThan(180_000)
    expect(diag).not.toBeNull()
  })
})
