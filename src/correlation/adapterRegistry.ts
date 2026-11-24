/**
 * Source adapter registry (Stage 23).
 * Orchestrator resolves adapters by kind — adding a format requires registration only.
 */

import type { AdapterKind, SourceAdapter } from './types'

const adapters = new Map<AdapterKind, SourceAdapter>()

export function registerSourceAdapter(adapter: SourceAdapter): void {
  adapters.set(adapter.kind, adapter)
}

export function unregisterSourceAdapter(kind: AdapterKind): void {
  adapters.delete(kind)
}

export function getSourceAdapter(kind: AdapterKind): SourceAdapter | null {
  return adapters.get(kind) ?? null
}

export function clearSourceAdapterRegistry(): void {
  adapters.clear()
}

export function registeredAdapterKinds(): readonly AdapterKind[] {
  return [...adapters.keys()]
}

export function requireSourceAdapter(kind: AdapterKind): SourceAdapter {
  const adapter = getSourceAdapter(kind)
  if (!adapter) {
    throw new Error(`No SourceAdapter registered for kind: ${kind}`)
  }
  return adapter
}
