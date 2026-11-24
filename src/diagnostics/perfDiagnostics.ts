/**
 * Non-content performance diagnostics (Stage 16 — production + test harness).
 * Must never log filenames, originals, pseudonyms or packet bytes.
 */

export interface PerfPhaseRecord {
  readonly name: string
  readonly startMs: number
  endMs?: number
}

export interface PerfDiagnosticSnapshot {
  readonly startedAtMs: number
  readonly phases: readonly PerfPhaseRecord[]
  timeToFirstProgressMs?: number
  timeToInteractiveMs?: number
  cancelLatencyMs?: number
  peakHeapBytes?: number
  longTaskCount: number
  longTaskMaxMs: number
  copyOperations: number
  copiedBytes: number
  transferredBytes: number
  inFlightBytes: number
  maxInFlightBytes: number
}

export interface PerfDiagnosticHook {
  markPhase(name: string): void
  endPhase(name: string): void
  recordFirstProgress(): void
  recordInteractive(): void
  recordCancel(startMs: number): void
  recordLongTask(durationMs: number): void
  recordCopy(byteLength: number): void
  recordTransfer(byteLength: number): void
  setInFlightBytes(bytes: number): void
  sampleHeap(): void
  snapshot(): PerfDiagnosticSnapshot
  reset(): void
}

declare global {
  interface Window {
    __rndLogAnonymizerPerfDiagnostics?: PerfDiagnosticHook
  }
}

let injectedHook: PerfDiagnosticHook | undefined

export function setPerfDiagnosticsHook(hook: PerfDiagnosticHook | undefined): void {
  injectedHook = hook
}

function heapUsedBytes(): number | undefined {
  const perf = performance as Performance & { memory?: { usedJSHeapSize: number } }
  return perf.memory?.usedJSHeapSize
}

export function createPerfDiagnosticHook(originMs: number = performance.now()): PerfDiagnosticHook {
  let startedAtMs = originMs
  const phases: PerfPhaseRecord[] = []
  let timeToFirstProgressMs: number | undefined
  let timeToInteractiveMs: number | undefined
  let cancelLatencyMs: number | undefined
  let peakHeapBytes: number | undefined
  let longTaskCount = 0
  let longTaskMaxMs = 0
  let copyOperations = 0
  let copiedBytes = 0
  let transferredBytes = 0
  let inFlightBytes = 0
  let maxInFlightBytes = 0

  const sampleHeap = () => {
    const used = heapUsedBytes()
    if (used === undefined) return
    peakHeapBytes =
      peakHeapBytes === undefined ? used : Math.max(peakHeapBytes, used)
  }

  return {
    markPhase(name) {
      phases.push({ name, startMs: performance.now() - startedAtMs })
    },
    endPhase(name) {
      const phase = [...phases].reverse().find((p) => p.name === name && p.endMs === undefined)
      if (phase) phase.endMs = performance.now() - startedAtMs
    },
    recordFirstProgress() {
      if (timeToFirstProgressMs === undefined) {
        timeToFirstProgressMs = performance.now() - startedAtMs
      }
    },
    recordInteractive() {
      if (timeToInteractiveMs === undefined) {
        timeToInteractiveMs = performance.now() - startedAtMs
      }
    },
    recordCancel(startMs) {
      cancelLatencyMs = performance.now() - startMs
    },
    recordLongTask(durationMs) {
      longTaskCount++
      longTaskMaxMs = Math.max(longTaskMaxMs, durationMs)
    },
    recordCopy(byteLength) {
      copyOperations++
      copiedBytes += byteLength
    },
    recordTransfer(byteLength) {
      transferredBytes += byteLength
    },
    setInFlightBytes(bytes) {
      inFlightBytes = bytes
      maxInFlightBytes = Math.max(maxInFlightBytes, bytes)
    },
    sampleHeap,
    snapshot() {
      sampleHeap()
      return {
        startedAtMs,
        phases: phases.map((p) => ({ ...p })),
        timeToFirstProgressMs,
        timeToInteractiveMs,
        cancelLatencyMs,
        peakHeapBytes,
        longTaskCount,
        longTaskMaxMs,
        copyOperations,
        copiedBytes,
        transferredBytes,
        inFlightBytes,
        maxInFlightBytes,
      }
    },
    reset() {
      startedAtMs = performance.now()
      phases.length = 0
      timeToFirstProgressMs = undefined
      timeToInteractiveMs = undefined
      cancelLatencyMs = undefined
      peakHeapBytes = undefined
      longTaskCount = 0
      longTaskMaxMs = 0
      copyOperations = 0
      copiedBytes = 0
      transferredBytes = 0
      inFlightBytes = 0
      maxInFlightBytes = 0
    },
  }
}

export function getActivePerfDiagnostics(): PerfDiagnosticHook | undefined {
  if (injectedHook) return injectedHook
  if (typeof globalThis === 'undefined') return undefined
  return (globalThis as typeof globalThis & { __rndLogAnonymizerPerfDiagnostics?: PerfDiagnosticHook })
    .__rndLogAnonymizerPerfDiagnostics
}

/** Install hook on globalThis for Playwright / manual browser profiling. */
export function installBrowserPerfDiagnostics(): PerfDiagnosticHook {
  const hook = createPerfDiagnosticHook()
  setPerfDiagnosticsHook(hook)
  if (typeof globalThis !== 'undefined') {
    ;(globalThis as typeof globalThis & { __rndLogAnonymizerPerfDiagnostics?: PerfDiagnosticHook }).__rndLogAnonymizerPerfDiagnostics =
      hook
  }
  return hook
}

export function getBrowserPerfDiagnostics(): PerfDiagnosticHook | undefined {
  return getActivePerfDiagnostics()
}

/** Observe long tasks when PerformanceObserver is available (Chromium). */
export function observeLongTasks(hook: PerfDiagnosticHook): (() => void) | undefined {
  if (typeof PerformanceObserver === 'undefined') return undefined
  try {
    const observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        hook.recordLongTask(entry.duration)
      }
    })
    observer.observe({ type: 'longtask', buffered: true })
    return () => observer.disconnect()
  } catch {
    return undefined
  }
}
