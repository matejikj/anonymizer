/**
 * Max-size release gate helpers — fixtures, perf diagnostics, network guard, reports.
 * Never logs filenames, originals, pseudonyms or packet bytes in diagnostics payloads.
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Page, TestInfo } from '@playwright/test'
import { expect } from '@playwright/test'
import {
  BYTES_PER_MIB,
  MAX_PCAP_FILE_BYTES,
  MAX_TEXT_FILE_BYTES,
} from '../../../../src/domain/capabilityContract.ts'
import {
  generateMicroClassicPcap,
  generateMicroPcapng,
  generateMicroText,
} from '../../maximumFixtureGenerators.ts'

const here = path.dirname(fileURLToPath(import.meta.url))
export const RELEASE_RESULTS_DIR = path.resolve(here, '../../results')
export const MAX_SIZE_FIXTURE_DIR = process.env.MAX_SIZE_FIXTURE_DIR
  ? path.resolve(process.env.MAX_SIZE_FIXTURE_DIR)
  : path.resolve(here, '../../fixtures/max-size')

/** Full 90/100 MiB browser gate — set in release CI. */
export const MAX_SIZE_FULL = process.env.MAX_SIZE_FULL === '1'

export const CANCEL_VISUAL_MS = 250
export const CANCEL_COMPLETE_MS = 1_000

export const HEAP_BUDGET_TEXT = 3.5
export const HEAP_BUDGET_PCAP_BLOB = 3.5

export type MaxSizeReportRow = {
  scenario: string
  browser: string
  inputBytes: number
  inputMiB: number
  wallMs: number
  exportMs?: number
  cancelLatencyMs?: number
  peakHeapBytes?: number
  heapBudgetRatio?: number
  crossOriginRequests: number
  diagnostics?: unknown
  fullGate: boolean
}

export function isFullReleaseGate(): boolean {
  return MAX_SIZE_FULL
}

export function textTargetBytes(): number {
  return MAX_SIZE_FULL ? MAX_TEXT_FILE_BYTES : 4 * BYTES_PER_MIB
}

export function pcapTargetBytes(): number {
  return MAX_SIZE_FULL ? MAX_PCAP_FILE_BYTES : 512 * 1024
}

export function fixtureFile(name: string): string {
  return path.join(MAX_SIZE_FIXTURE_DIR, name)
}

export function ensureFixtureDir(): void {
  fs.mkdirSync(MAX_SIZE_FIXTURE_DIR, { recursive: true })
}

export function resolveTextFixture(lineEnding: 'lf' | 'crlf'): { filePath: string; byteLength: number } {
  const fullName = lineEnding === 'crlf' ? 'maximum-90mib-crlf.log' : 'maximum-90mib-lf.log'
  const fullPath = fixtureFile(fullName)
  if (MAX_SIZE_FULL && fs.existsSync(fullPath)) {
    return { filePath: fullPath, byteLength: fs.statSync(fullPath).size }
  }
  ensureFixtureDir()
  const microName = `max-size-micro-${lineEnding}.log`
  const microPath = fixtureFile(microName)
  if (!fs.existsSync(microPath)) {
    const fixture = generateMicroText(textTargetBytes(), lineEnding)
    fs.writeFileSync(microPath, fixture.text)
  }
  return { filePath: microPath, byteLength: fs.statSync(microPath).size }
}

export function resolvePcapFixtureForCancel(): { filePath: string; byteLength: number } {
  ensureFixtureDir()
  const cancelBytes = MAX_SIZE_FULL ? MAX_PCAP_FILE_BYTES : 32 * BYTES_PER_MIB
  const microPath = fixtureFile(`max-size-cancel-${cancelBytes}.pcap`)
  if (!fs.existsSync(microPath)) {
    const fixture = generateMicroClassicPcap(cancelBytes)
    fs.writeFileSync(microPath, fixture.buffer)
  }
  return { filePath: microPath, byteLength: fs.statSync(microPath).size }
}

export function resolvePcapFixture(kind: 'classic' | 'pcapng'): { filePath: string; byteLength: number } {
  const fullName = kind === 'pcapng' ? 'maximum-100mib.pcapng' : 'maximum-100mib.pcap'
  const fullPath = fixtureFile(fullName)
  if (MAX_SIZE_FULL && fs.existsSync(fullPath)) {
    return { filePath: fullPath, byteLength: fs.statSync(fullPath).size }
  }
  ensureFixtureDir()
  const microName = kind === 'pcapng' ? 'max-size-micro.pcapng' : 'max-size-micro.pcap'
  const microPath = fixtureFile(microName)
  if (!fs.existsSync(microPath)) {
    const bytes = pcapTargetBytes()
    const fixture =
      kind === 'pcapng' ? generateMicroPcapng(bytes) : generateMicroClassicPcap(bytes)
    fs.writeFileSync(microPath, fixture.buffer)
  }
  return { filePath: microPath, byteLength: fs.statSync(microPath).size }
}

export function writeMaxSizeReport(row: MaxSizeReportRow): void {
  fs.mkdirSync(RELEASE_RESULTS_DIR, { recursive: true })
  const safeScenario = row.scenario.replace(/[^a-z0-9-]+/gi, '-').toLowerCase()
  const file = path.join(RELEASE_RESULTS_DIR, `max-size-${safeScenario}-${row.browser}.json`)
  fs.writeFileSync(file, JSON.stringify({ ...row, recordedAt: new Date().toISOString() }, null, 2))
}

export async function installPerfDiagnosticsInitScript(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const phases: Array<{ name: string; startMs: number; endMs?: number }> = []
    const origin = performance.now()
    let ttfp: number | undefined
    let tti: number | undefined
    let cancelLatencyMs: number | undefined
    let peakHeapBytes: number | undefined
    let longTaskCount = 0
    let longTaskMaxMs = 0
    let transferredBytes = 0
    let maxInFlightBytes = 0

    const sampleHeap = () => {
      const perf = performance as Performance & { memory?: { usedJSHeapSize: number } }
      const used = perf.memory?.usedJSHeapSize
      if (used === undefined) return
      peakHeapBytes = peakHeapBytes === undefined ? used : Math.max(peakHeapBytes, used)
    }

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
      recordCancel(startMs: number) {
        cancelLatencyMs = performance.now() - startMs
      },
      recordTransfer(n: number) {
        transferredBytes += n
      },
      setInFlightBytes(n: number) {
        maxInFlightBytes = Math.max(maxInFlightBytes, n)
      },
      recordLongTask(ms: number) {
        longTaskCount++
        longTaskMaxMs = Math.max(longTaskMaxMs, ms)
      },
      sampleHeap,
      snapshot() {
        sampleHeap()
        return {
          phases,
          timeToFirstProgressMs: ttfp,
          timeToInteractiveMs: tti,
          cancelLatencyMs,
          peakHeapBytes,
          longTaskCount,
          longTaskMaxMs,
          transferredBytes,
          maxInFlightBytes,
        }
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
}

export async function readPerfSnapshot(page: Page): Promise<unknown> {
  return page.evaluate(() => {
    const hook = (globalThis as typeof globalThis & {
      __rndLogAnonymizerPerfDiagnostics?: { snapshot(): unknown }
    }).__rndLogAnonymizerPerfDiagnostics
    return hook?.snapshot() ?? null
  })
}

export function attachNetworkMonitor(page: Page): { crossOrigin: string[]; stop: () => void } {
  const crossOrigin: string[] = []
  let origin = ''
  const handler = (request: { url: () => string }) => {
    const url = request.url()
    if (!url.startsWith('http://') && !url.startsWith('https://')) return
    if (!origin) {
      try {
        origin = new URL(page.url()).origin
      } catch {
        return
      }
    }
    if (!url.startsWith(origin)) crossOrigin.push(url)
  }
  page.on('request', handler)
  return {
    crossOrigin,
    stop: () => page.off('request', handler),
  }
}

export async function assertUiRemainsInteractive(page: Page, testId: string): Promise<void> {
  const el = page.getByTestId(testId)
  await el.waitFor({ state: 'visible', timeout: 5_000 })
  const box = await el.boundingBox()
  expect(box).not.toBeNull()
  expect(box!.width).toBeGreaterThan(0)
}

export async function assertCancelWithinLimits(
  page: Page,
  clickCancel: () => Promise<void>,
): Promise<number> {
  const t0 = Date.now()
  await clickCancel()
  const visualMs = Date.now() - t0
  expect(visualMs).toBeLessThanOrEqual(CANCEL_VISUAL_MS + 500)

  await page.waitForFunction(
    () => {
      const progress = document.querySelector('[data-testid="pcap-progress"]')
      const empty = document.querySelector('[data-testid="pcap-empty"]')
      const choose = document.querySelector('[data-testid="multi-source-dropzone"]')
      return !progress || !!empty || !!choose
    },
    { timeout: CANCEL_COMPLETE_MS + 500 },
  )
  const completeMs = Date.now() - t0
  expect(completeMs).toBeLessThanOrEqual(CANCEL_COMPLETE_MS + 500)

  await page.evaluate((startMs) => {
    const hook = (globalThis as typeof globalThis & {
      __rndLogAnonymizerPerfDiagnostics?: { recordCancel(ms: number): void }
    }).__rndLogAnonymizerPerfDiagnostics
    hook?.recordCancel(startMs)
  }, t0)

  return completeMs
}

export async function sampleChromiumHeap(page: Page): Promise<number | undefined> {
  return page.evaluate(() => {
    const perf = performance as Performance & { memory?: { usedJSHeapSize: number } }
    return perf.memory?.usedJSHeapSize
  })
}

export function textLeakCanaries(): readonly string[] {
  return [
    'canary.stage0@corp.example.invalid',
    'canary-host.stage0.example.invalid',
    '10.99.88.77',
    '550e8400-e29b-41d4-a716-446655440000',
    'Stage0Secret!',
    'sk-baseline-canary-not-real',
    'secret-dns-canary.stage0.example.invalid',
    'TLS_MASTER_SECRET_STAGE0_CANARY',
  ]
}

export function assertExportMustNotLeak(body: string): void {
  for (const token of textLeakCanaries()) {
    expect(body).not.toContain(token)
  }
}

export async function writeTempLog(content: string, name: string): Promise<string> {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'rnd-max-size-'))
  const filePath = path.join(dir, name)
  await fs.promises.writeFile(filePath, content, 'utf8')
  return filePath
}

export function recordScenario(
  testInfo: TestInfo,
  row: Omit<MaxSizeReportRow, 'browser' | 'fullGate'>,
): void {
  writeMaxSizeReport({
    ...row,
    browser: testInfo.project.name,
    fullGate: MAX_SIZE_FULL,
  })
}
