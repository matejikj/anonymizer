/**
 * BufferLease — explicit ownership for hydrated packet/reassembly bytes.
 * Parsers must not retain views after release; instrumentation counts live raw bytes.
 */

import { PCAP_KERNEL_BUDGETS } from '../../domain/capabilityContract'

export type LeaseOwner =
  | 'pull-reader'
  | 'packet-copy'
  | 'window-hydrate'
  | 'reassembly'
  | 'preview'
  | 'scratch'
  | 'test'

export interface BufferLease {
  readonly id: number
  readonly owner: LeaseOwner
  readonly byteLength: number
  readonly bytes: Uint8Array
  release(): void
}

export interface LeaseStats {
  readonly liveLeases: number
  readonly liveBytes: number
  readonly peakBytes: number
  readonly totalAcquired: number
  readonly totalReleased: number
}

export class BufferLeaseArena {
  private nextId = 1
  private live = new Map<number, { owner: LeaseOwner; byteLength: number }>()
  private _peakBytes = 0
  private _totalAcquired = 0
  private _totalReleased = 0
  private readonly maxRawBytes: number

  constructor(maxRawBytes: number = PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes) {
    this.maxRawBytes = maxRawBytes
  }

  get stats(): LeaseStats {
    let liveBytes = 0
    for (const entry of this.live.values()) liveBytes += entry.byteLength
    return {
      liveLeases: this.live.size,
      liveBytes,
      peakBytes: this._peakBytes,
      totalAcquired: this._totalAcquired,
      totalReleased: this._totalReleased,
    }
  }

  /** Reserve then wrap. Throws a safe budget code when aggregate would exceed the cap. */
  acquire(owner: LeaseOwner, bytes: Uint8Array): BufferLease {
    const byteLength = bytes.byteLength
    const current = this.stats.liveBytes
    if (current + byteLength > this.maxRawBytes) {
      throw new KernelBudgetError('raw-buffers-exceeded', owner, current + byteLength, this.maxRawBytes)
    }
    const id = this.nextId++
    this.live.set(id, { owner, byteLength })
    this._totalAcquired++
    const liveBytes = current + byteLength
    if (liveBytes > this._peakBytes) this._peakBytes = liveBytes

    let released = false
    return {
      id,
      owner,
      byteLength,
      bytes,
      release: () => {
        if (released) return
        released = true
        this.live.delete(id)
        this._totalReleased++
      },
    }
  }

  /** Test helper — force-release everything (generation abort). */
  releaseAll(): void {
    this.live.clear()
  }
}

export class KernelBudgetError extends Error {
  readonly code: string
  readonly owner: LeaseOwner
  readonly requested: number
  readonly limit: number

  constructor(code: string, owner: LeaseOwner, requested: number, limit: number) {
    super(`Kernel budget ${code} (owner=${owner})`)
    this.name = 'KernelBudgetError'
    this.code = code
    this.owner = owner
    this.requested = requested
    this.limit = limit
  }
}
