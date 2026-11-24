/**
 * Session budget accountant — reserves before large allocations; never spills to storage.
 */

import { PCAP_KERNEL_BUDGETS } from '../../domain/capabilityContract'
import { KernelBudgetError, type LeaseOwner } from './leases'

export type BudgetChannel =
  | 'raw'
  | 'reassembly'
  | 'journal'
  | 'mapping'
  | 'preview'

export interface BudgetSnapshot {
  readonly rawBytes: number
  readonly reassemblyBytes: number
  readonly journalBytes: number
  readonly mappingBytes: number
  readonly previewBytes: number
  readonly peakRawBytes: number
  readonly peakJournalBytes: number
}

export class SessionBudgetAccountant {
  private rawBytes = 0
  private reassemblyBytes = 0
  private journalBytes = 0
  private mappingBytes = 0
  private previewBytes = 0
  private peakRawBytes = 0
  private peakJournalBytes = 0

  snapshot(): BudgetSnapshot {
    return {
      rawBytes: this.rawBytes,
      reassemblyBytes: this.reassemblyBytes,
      journalBytes: this.journalBytes,
      mappingBytes: this.mappingBytes,
      previewBytes: this.previewBytes,
      peakRawBytes: this.peakRawBytes,
      peakJournalBytes: this.peakJournalBytes,
    }
  }

  /** Live raw aggregate = read-ahead/scratch + reassembly + preview. */
  private liveRawAggregate(): number {
    return this.rawBytes + this.reassemblyBytes + this.previewBytes
  }

  reserve(channel: BudgetChannel, bytes: number, owner: LeaseOwner = 'scratch'): void {
    if (bytes < 0) throw new Error('budget reserve must be non-negative')
    switch (channel) {
      case 'raw': {
        const next = this.liveRawAggregate() + bytes
        if (next > PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes) {
          throw new KernelBudgetError('raw-buffers-exceeded', owner, next, PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes)
        }
        this.rawBytes += bytes
        if (next > this.peakRawBytes) this.peakRawBytes = next
        break
      }
      case 'reassembly': {
        if (this.reassemblyBytes + bytes > PCAP_KERNEL_BUDGETS.reassemblyMaxBytes) {
          throw new KernelBudgetError(
            'reassembly-exceeded',
            'reassembly',
            this.reassemblyBytes + bytes,
            PCAP_KERNEL_BUDGETS.reassemblyMaxBytes,
          )
        }
        const next = this.liveRawAggregate() + bytes
        if (next > PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes) {
          throw new KernelBudgetError('raw-buffers-exceeded', 'reassembly', next, PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes)
        }
        this.reassemblyBytes += bytes
        if (next > this.peakRawBytes) this.peakRawBytes = next
        break
      }
      case 'preview': {
        if (this.previewBytes + bytes > PCAP_KERNEL_BUDGETS.previewCacheMaxBytes) {
          throw new KernelBudgetError(
            'preview-exceeded',
            'preview',
            this.previewBytes + bytes,
            PCAP_KERNEL_BUDGETS.previewCacheMaxBytes,
          )
        }
        const next = this.liveRawAggregate() + bytes
        if (next > PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes) {
          throw new KernelBudgetError('raw-buffers-exceeded', 'preview', next, PCAP_KERNEL_BUDGETS.rawBuffersMaxBytes)
        }
        this.previewBytes += bytes
        if (next > this.peakRawBytes) this.peakRawBytes = next
        break
      }
      case 'journal':
        if (this.journalBytes + bytes > PCAP_KERNEL_BUDGETS.journalMaxBytes) {
          throw new KernelBudgetError(
            'journal-exceeded',
            owner,
            this.journalBytes + bytes,
            PCAP_KERNEL_BUDGETS.journalMaxBytes,
          )
        }
        this.journalBytes += bytes
        if (this.journalBytes > this.peakJournalBytes) this.peakJournalBytes = this.journalBytes
        break
      case 'mapping':
        if (this.mappingBytes + bytes > PCAP_KERNEL_BUDGETS.mappingMaxBytes) {
          throw new KernelBudgetError(
            'mapping-exceeded',
            owner,
            this.mappingBytes + bytes,
            PCAP_KERNEL_BUDGETS.mappingMaxBytes,
          )
        }
        this.mappingBytes += bytes
        break
      default: {
        const _exhaustive: never = channel
        void _exhaustive
      }
    }
  }

  release(channel: BudgetChannel, bytes: number): void {
    const n = Math.max(0, bytes)
    switch (channel) {
      case 'raw':
        this.rawBytes = Math.max(0, this.rawBytes - n)
        break
      case 'reassembly':
        this.reassemblyBytes = Math.max(0, this.reassemblyBytes - n)
        break
      case 'preview':
        this.previewBytes = Math.max(0, this.previewBytes - n)
        break
      case 'journal':
        this.journalBytes = Math.max(0, this.journalBytes - n)
        break
      case 'mapping':
        this.mappingBytes = Math.max(0, this.mappingBytes - n)
        break
      default: {
        const _exhaustive: never = channel
        void _exhaustive
      }
    }
  }
}
