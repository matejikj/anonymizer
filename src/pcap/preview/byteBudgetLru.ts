/**
 * Byte-budget LRU cache (Stage 9) — evicts by least-recently-used until under budget.
 */

export interface LruStats {
  entries: number
  bytesUsed: number
  byteBudget: number
}

export class ByteBudgetLru<K, V> {
  private readonly map = new Map<K, { value: V; bytes: number }>()
  private bytesUsed = 0
  private readonly byteBudget: number

  constructor(byteBudget: number) {
    this.byteBudget = byteBudget
  }

  get size(): number {
    return this.map.size
  }

  get(key: K): V | undefined {
    const entry = this.map.get(key)
    if (!entry) return undefined
    this.map.delete(key)
    this.map.set(key, entry)
    return entry.value
  }

  set(key: K, value: V, bytes: number): void {
    if (bytes > this.byteBudget) return
    const existing = this.map.get(key)
    if (existing) {
      this.bytesUsed -= existing.bytes
      this.map.delete(key)
    }
    this.map.set(key, { value, bytes })
    this.bytesUsed += bytes
    this.evict()
  }

  delete(key: K): void {
    const entry = this.map.get(key)
    if (!entry) return
    this.bytesUsed -= entry.bytes
    this.map.delete(key)
  }

  clear(): void {
    this.map.clear()
    this.bytesUsed = 0
  }

  stats(): LruStats {
    return { entries: this.map.size, bytesUsed: this.bytesUsed, byteBudget: this.byteBudget }
  }

  private evict(): void {
    while (this.bytesUsed > this.byteBudget && this.map.size > 0) {
      const oldest = this.map.keys().next().value as K
      const entry = this.map.get(oldest)!
      this.bytesUsed -= entry.bytes
      this.map.delete(oldest)
    }
  }
}
