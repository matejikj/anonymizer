import { describe, expect, it, afterEach } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority.ts'
import { MappingWorkerClient, type WorkerLike } from '../../src/mapping/mappingWorkerClient.ts'
import {
  validateProtocolVersion,
  validateResolveIdentities,
  snapshotToWire,
  type MappingWorkerRequest,
  type MappingWorkerResponse,
} from '../../src/mapping/protocol.ts'
import {
  resolvePcapIdentities,
  resetPcapMappingClient,
  setPcapMappingClientForTests,
  aliasFromSnapshot,
} from '../../src/pcap/mapping/pcapMappingPort.ts'
import { buildAliasLookup } from '../../src/mapping/types.ts'

function createInProcessWorkerFactory(): () => WorkerLike {
  const authority = new MappingAuthority()
  return () => {
    const listeners = new Set<(ev: MessageEvent) => void>()
    const emit = (response: MappingWorkerResponse) => {
      for (const fn of listeners) fn({ data: response } as MessageEvent)
    }
    return {
      postMessage(message: unknown) {
        const msg = message as MappingWorkerRequest
        queueMicrotask(() => {
          const versionErr = validateProtocolVersion(msg.protocolVersion)
          if (versionErr) {
            emit({ type: 'error', requestId: 'requestId' in msg ? msg.requestId : 'unknown', code: versionErr.code, message: versionErr.message })
            return
          }
          if (msg.type === 'resolve') {
            const validated = validateResolveIdentities(msg.identities)
            if (!validated.ok) {
              emit({ type: 'error', requestId: msg.requestId, generationId: msg.generationId, code: validated.error.code, message: validated.error.message })
              return
            }
            const result = authority.resolve(
              { generationId: msg.generationId, sourceId: msg.sourceId, identities: validated.identities },
              msg.config,
            )
            if (!result.ok) {
              emit({ type: 'error', requestId: msg.requestId, generationId: msg.generationId, code: result.code, message: result.message })
              return
            }
            emit({ type: 'resolved', requestId: msg.requestId, generationId: msg.generationId, snapshot: snapshotToWire(result.snapshot) })
          }
        })
      },
      terminate() { listeners.clear() },
      addEventListener(_: 'message', fn: (ev: MessageEvent) => void) { listeners.add(fn) },
      removeEventListener(_: 'message', fn: (ev: MessageEvent) => void) { listeners.delete(fn) },
    }
  }
}

describe('pcap mapping port', () => {
  afterEach(() => {
    setPcapMappingClientForTests(null)
    resetPcapMappingClient()
  })

  it('resolves PCAP identities through mapping worker client', async () => {
    setPcapMappingClientForTests(new MappingWorkerClient(createInProcessWorkerFactory()))
    const snapshot = await resolvePcapIdentities('gen-pcap', 'capture-1', [
      { category: 'ipv4', canonical: '192.168.50.1' },
      { category: 'ipv4', canonical: '192.168.50.1' },
    ])
    expect(snapshot.entries.length).toBe(1)
    expect(aliasFromSnapshot(snapshot, 'ipv4', '192.168.50.1')).toBe(snapshot.entries[0]!.alias)
    expect(snapshot.entries[0]!.occurrenceCount).toBe(2)
  })

  it('PF-04: buildAliasLookup caches per snapshot identity instead of rebuilding on every call', async () => {
    setPcapMappingClientForTests(new MappingWorkerClient(createInProcessWorkerFactory()))
    const snapshot = await resolvePcapIdentities('gen-pcap', 'capture-cache', [
      { category: 'ipv4', canonical: '192.168.60.1' },
    ])
    const first = buildAliasLookup(snapshot)
    const second = buildAliasLookup(snapshot)
    expect(second).toBe(first)
  })

  it('PF-04: a new revision snapshot is not served from a stale cached lookup', async () => {
    setPcapMappingClientForTests(new MappingWorkerClient(createInProcessWorkerFactory()))
    const first = await resolvePcapIdentities('gen-pcap', 'capture-revision', [
      { category: 'ipv4', canonical: '192.168.70.1' },
    ])
    const firstLookup = buildAliasLookup(first)
    expect(firstLookup.get('ipv4:192.168.70.1')).toBe(first.entries[0]!.alias)

    const second = await resolvePcapIdentities('gen-pcap', 'capture-revision', [
      { category: 'ipv4', canonical: '192.168.70.1' },
      { category: 'ipv4', canonical: '192.168.70.2' },
    ])
    expect(second).not.toBe(first)
    const secondLookup = buildAliasLookup(second)
    expect(secondLookup).not.toBe(firstLookup)
    expect(secondLookup.get('ipv4:192.168.70.2')).toBe(
      second.entries.find((e) => e.canonical === '192.168.70.2')!.alias,
    )
    // Original snapshot's cached lookup must remain unaffected by the later resolve.
    expect(buildAliasLookup(first)).toBe(firstLookup)
  })
})
