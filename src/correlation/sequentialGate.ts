/**
 * Bounded concurrency gate — serializes correlation pipeline steps (Stage 23).
 */

export class SequentialGate {
  private tail: Promise<void> = Promise.resolve()
  private running = false

  get isRunning(): boolean {
    return this.running
  }

  run<T>(label: string, fn: () => Promise<T>): Promise<T> {
    const runPromise = this.tail.then(async () => {
      if (this.running) {
        throw new Error(`SequentialGate already running (${label})`)
      }
      this.running = true
      try {
        return await fn()
      } finally {
        this.running = false
      }
    })
    this.tail = runPromise.then(
      () => undefined,
      () => undefined,
    )
    return runPromise
  }

  reset(): void {
    this.tail = Promise.resolve()
    this.running = false
  }
}

/** Shared resolve/discover serialization — prevents parallel alias allocation races. */
export const correlationResolveGate = new SequentialGate()
