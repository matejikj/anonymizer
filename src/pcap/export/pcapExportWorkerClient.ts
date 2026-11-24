/**
 * PCAP export worker lifecycle — incremental streaming export only (Stage 13).
 */

let worker: Worker | null = null

/** Inline `new URL(..., import.meta.url)` so Vite emits a real worker bundle. */
export function createPcapExportWorker(): Worker {
  return new Worker(new URL('../../workers/pcap-export.worker.ts', import.meta.url), {
    type: 'module',
  })
}

function getWorker(): Worker {
  if (!worker) worker = createPcapExportWorker()
  return worker
}

export function getPcapExportWorker(): Worker {
  return getWorker()
}

export function disposePcapExportWorker(): void {
  worker?.terminate()
  worker = null
}
