import { describe, expect, it, beforeEach, afterEach } from 'vitest'
import { MappingAuthority } from '../../src/mapping/mappingAuthority'
import { MappingWorkerClient, type WorkerLike } from '../../src/mapping/mappingWorkerClient'
import { DEFAULT_MAPPING_CONFIG } from '../../src/pcap/anonymization/mapping'
import {
  MAPPING_PROTOCOL_VERSION,
  MAPPING_WORKER_ERROR,
  validateProtocolVersion,
  validateResolveIdentities,
  snapshotToWire,
  type MappingWorkerRequest,
  type MappingWorkerResponse,
} from '../../src/mapping/protocol'

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
            emit({
              type: 'error',
              requestId: 'requestId' in msg ? msg.requestId : 'unknown',
              code: versionErr.code,
              message: versionErr.message,
            })
            return
          }

          if (msg.type === 'ping') {
            emit({ type: 'pong', requestId: msg.requestId, revision: authority.getRevision() })
            return
          }

          if (msg.type === 'cancel') {
            authority.requestCancel(msg.generationId)
            emit({ type: 'pong', requestId: msg.requestId, revision: authority.getRevision() })
            return
          }

          if (msg.type === 'resolve') {
            const validated = validateResolveIdentities(msg.identities)
            if (!validated.ok) {
              emit({
                type: 'error',
                requestId: msg.requestId,
                generationId: msg.generationId,
                code: validated.error.code,
                message: validated.error.message,
              })
              return
            }

            const result = authority.resolve({
              generationId: msg.generationId,
              sourceId: msg.sourceId,
              identities: validated.identities,
            }, msg.config)

            if (!result.ok) {
              emit({
                type: 'error',
                requestId: msg.requestId,
                generationId: msg.generationId,
                code: result.code,
                message: result.message,
              })
              return
            }

            emit({
              type: 'resolved',
              requestId: msg.requestId,
              generationId: msg.generationId,
              snapshot: snapshotToWire(result.snapshot),
            })
          }
        })
      },
      terminate() {
        listeners.clear()
      },
      addEventListener(_type: 'message', listener: (ev: MessageEvent) => void) {
        listeners.add(listener)
      },
      removeEventListener(_type: 'message', listener: (ev: MessageEvent) => void) {
        listeners.delete(listener)
      },
    }
  }
}

describe('MappingWorkerClient', () => {
  let client: MappingWorkerClient

  beforeEach(() => {
    client = new MappingWorkerClient(createInProcessWorkerFactory())
  })

  afterEach(() => {
    client.terminate()
  })

  it('resolves identities off the main mapping loop via worker messages', async () => {
    const snapshot = await client.resolve('gen-1', 'pcap-a', [{
      category: 'ipv4',
      canonical: '10.1.2.3',
      constraint: { kind: 'ipv4-wire' },
    }])
    expect(snapshot.revision).toBe(1)
    expect(snapshot.entries[0]!.alias).toMatch(/^10\.254\./)
    expect(client.getPublishedRevision()).toBe(1)
  })

  it('reuses alias on second resolve in same worker session', async () => {
    const first = await client.resolve('g1', 'pcap', [{
      category: 'mac',
      canonical: 'de:ad:be:ef:00:01',
      constraint: { kind: 'mac-wire' },
    }])
    const second = await client.resolve('g2', 'pcap', [{
      category: 'mac',
      canonical: 'de:ad:be:ef:00:01',
      constraint: { kind: 'mac-wire' },
    }])
    expect(second.entries[0]!.alias).toBe(first.entries[0]!.alias)
    expect(second.revision).toBe(2)
  })

  it('applies mapping config supplied with the worker request', async () => {
    const inputs = Array.from({ length: 8 }, (_, index) => ({
      category: 'port' as const,
      canonical: `tcp/${50000 + index}`,
      constraint: { kind: 'port-wire' as const, protocol: 'tcp' as const },
    }))
    const snapshot = await client.resolve('g-port', 'pcap', inputs, {
      ...DEFAULT_MAPPING_CONFIG,
      ephemeralPorts: 'permute',
    })

    const aliases = snapshot.entries.map((entry) => entry.alias)
    expect(aliases.some((alias, index) => alias !== inputs[index]!.canonical)).toBe(true)
    for (const [index, alias] of aliases.entries()) {
      const [protocol, rawPort] = alias.split('/')
      const port = Number(rawPort)
      expect(protocol).toBe('tcp')
      expect(port).toBeGreaterThanOrEqual(1024)
      expect(port).toBeLessThanOrEqual(65535)
      if (alias !== inputs[index]!.canonical) {
        expect(snapshot.entries[index]!.disposition).toBe('bijective')
      }
    }
  })

  it('clears published snapshot after terminate (Stage 19 lifecycle)', async () => {
    await client.resolve('gen-t', 'pcap', [{
      category: 'ipv4',
      canonical: '8.8.8.8',
      constraint: { kind: 'ipv4-wire' },
    }])
    client.terminate()
    expect(client.getPublishedSnapshot()).toBeNull()
    expect(client.getPublishedRevision()).toBe(0)
  })

  it('rejects invalid protocol version from worker path', async () => {
    const badFactory = () => {
      const inner = createInProcessWorkerFactory()()
      return {
        ...inner,
        postMessage(message: unknown) {
          const msg = message as MappingWorkerRequest
          if ('protocolVersion' in msg) msg.protocolVersion = 0
          inner.postMessage(msg)
        },
      }
    }
    const badClient = new MappingWorkerClient(badFactory)
    await expect(
      badClient.resolve('g', 's', [{ category: 'ipv4', canonical: '1.2.3.4', constraint: { kind: 'ipv4-wire' } }]),
    ).rejects.toThrow()
    badClient.terminate()
  })

  it('ignores stale response when request id does not match', async () => {
    const staleFactory = () => {
      const inner = createInProcessWorkerFactory()()
      const listeners = new Set<(ev: MessageEvent) => void>()
      return {
        postMessage(message: unknown) {
          inner.postMessage(message)
          queueMicrotask(() => {
            for (const fn of listeners) {
              fn({
                data: {
                  type: 'resolved',
                  requestId: 'stale-request',
                  generationId: 'gen-stale',
                  snapshot: {
                    scope: 'session',
                    revision: 99,
                    mappingRevision: 99,
                    generationId: 'gen-stale',
                    sourceId: 'x',
                    overflow: false,
                    entries: [],
                  },
                },
              } as MessageEvent)
            }
          })
        },
        terminate: () => inner.terminate(),
        addEventListener: (_: 'message', fn: (ev: MessageEvent) => void) => { listeners.add(fn); inner.addEventListener('message', fn) },
        removeEventListener: (_: 'message', fn: (ev: MessageEvent) => void) => { listeners.delete(fn); inner.removeEventListener('message', fn) },
      }
    }

    const staleClient = new MappingWorkerClient(staleFactory)
    const snapshot = await staleClient.resolve('gen-ok', 'pcap', [{
      category: 'ipv4',
      canonical: '1.1.1.1',
      constraint: { kind: 'ipv4-wire' },
    }])
    expect(snapshot.revision).toBe(1)
    expect(staleClient.getPublishedRevision()).toBe(1)
    staleClient.terminate()
  })

  it('rejects oversize batch at protocol layer', async () => {
    const identities = Array.from({ length: 500_001 }, (_, i) => ({
      category: 'ipv4' as const,
      canonical: `10.${(i >> 16) & 0xff}.${(i >> 8) & 0xff}.${i & 0xff}`,
      constraint: { kind: 'ipv4-wire' as const },
    }))
    await expect(client.resolve('big', 'pcap', identities)).rejects.toThrow()
    expect(client.getPublishedSnapshot()).toBeNull()
  })
})

describe('mapping worker protocol version guard', () => {
  it('uses current protocol version constant', () => {
    expect(MAPPING_PROTOCOL_VERSION).toBe(5)
    expect(MAPPING_WORKER_ERROR.invalidVersion).toBe('invalid-protocol-version')
  })
})
