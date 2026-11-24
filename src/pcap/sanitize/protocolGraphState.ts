/**
 * R08 — mapping-scoped protocol graph/tracker storage with explicit session dispose.
 */

import type { MappingLike } from '../anonymization/mapping.ts'

type MappingHandle = object

const stateByMapping = new WeakMap<MappingHandle, Map<string, unknown>>()
const registeredMappings = new Set<MappingHandle>()

/** Bumps on session dispose so graphs do not merge across capture generations on one mapping. */
let captureGeneration = 0

export function protocolGraphCaptureGeneration(): string {
  return String(captureGeneration)
}

function bucketFor(mapping: MappingLike): Map<string, unknown> {
  const key = mapping as MappingHandle
  let bucket = stateByMapping.get(key)
  if (!bucket) {
    bucket = new Map()
    stateByMapping.set(key, bucket)
    registeredMappings.add(key)
  }
  return bucket
}

export function protocolGraphEntry<T>(
  mapping: MappingLike,
  storeKey: string,
  factory: () => T,
): T {
  const bucket = bucketFor(mapping)
  let entry = bucket.get(storeKey)
  if (!entry) {
    entry = factory()
    bucket.set(storeKey, entry)
  }
  return entry as T
}

/** TCP transport session scope (V17-style), stable for client/server direction. */
export function tcpTransportSessionKey(input: {
  readonly srcIp?: string
  readonly dstIp?: string
  readonly srcPort: number
  readonly dstPort: number
}): string {
  const aIp = input.srcIp ?? '?'
  const bIp = input.dstIp ?? '?'
  const aPort = input.srcPort
  const bPort = input.dstPort
  if (aIp < bIp || (aIp === bIp && aPort <= bPort)) {
    return `tcp:${aIp}:${aPort}<->${bIp}:${bPort}`
  }
  return `tcp:${bIp}:${bPort}<->${aIp}:${aPort}`
}

/** Release all protocol graphs/trackers tied to the active mapping session. */
export function disposeProtocolGraphStateForSession(): void {
  for (const key of registeredMappings) {
    stateByMapping.delete(key)
  }
  registeredMappings.clear()
  captureGeneration += 1
}

/** Test-only: clear registry when mapping handles are still strongly reachable. */
export function resetProtocolGraphStateRegistryForTests(): void {
  disposeProtocolGraphStateForSession()
}
