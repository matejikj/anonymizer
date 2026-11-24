/** Worker entry URLs — keeps Vite emitting both workers in the production graph. */

export const DETECTION_WORKER_URL = new URL('./detection.worker.ts', import.meta.url)
export const EXPORT_WORKER_URL = new URL('./export.worker.ts', import.meta.url)
export const MAPPING_WORKER_URL = new URL('./mapping.worker.ts', import.meta.url)
export const PCAP_PROCESSING_WORKER_URL = new URL('./pcap-processing.worker.ts', import.meta.url)
