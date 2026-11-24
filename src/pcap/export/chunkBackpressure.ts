/**
 * Export chunk backpressure — max unconfirmed chunks between worker and main thread (Stage 12).
 * Step 3: per-stream gates so anonymized and recovery phases stay independently paced.
 */

export const PCAP_EXPORT_MAX_IN_FLIGHT_CHUNKS = 2

export type ExportStreamId = 'anonymized' | 'recovery'

/** Worker-side gate: blocks until an ACK frees a slot. */
export class WorkerChunkBackpressure {
  private inFlight = 0
  private readonly waiters: Array<() => void> = []

  async acquire(): Promise<void> {
    while (this.inFlight >= PCAP_EXPORT_MAX_IN_FLIGHT_CHUNKS) {
      await new Promise<void>((resolve) => {
        this.waiters.push(resolve)
      })
    }
    this.inFlight += 1
  }

  ack(): void {
    this.inFlight = Math.max(0, this.inFlight - 1)
    const wake = this.waiters.shift()
    if (wake) wake()
  }

  reset(): void {
    this.inFlight = 0
    this.waiters.length = 0
  }
}

/** Dual-stream backpressure — only the active stream should have in-flight chunks. */
export class DualStreamChunkBackpressure {
  private readonly streams = new Map<ExportStreamId, WorkerChunkBackpressure>([
    ['anonymized', new WorkerChunkBackpressure()],
    ['recovery', new WorkerChunkBackpressure()],
  ])

  async acquire(streamId: ExportStreamId = 'anonymized'): Promise<void> {
    await this.streams.get(streamId)!.acquire()
  }

  ack(streamId: ExportStreamId = 'anonymized'): void {
    this.streams.get(streamId)?.ack()
  }

  reset(): void {
    for (const gate of this.streams.values()) gate.reset()
  }
}
