/**
 * T74 — capture-scoped flow / cluster statistics for proprietary light inference.
 *
 * Budgets from PCAP_KERNEL_BUDGETS; exceeding fails closed (mask that flow).
 */

import { PCAP_KERNEL_BUDGETS } from '../../../domain/capabilityContract.ts'

export type ProprietaryFlowKey = string

export type ProprietaryFieldClass =
  | 'known-identity'
  | 'text'
  | 'sender-bound-id'
  | 'location'
  | 'timestamp'
  | 'constant'
  | 'counter'
  | 'media-entropy'
  | 'unclassified'

interface OffsetStat {
  readonly width: 1 | 2 | 4 | 8
  values: Map<string, number>
  /** Distinct sender keys that produced each value. */
  valueSenders: Map<string, Set<string>>
  monoUp: boolean
  monoDown: boolean
  lastNum: number | null
}

interface ClusterState {
  messageCount: number
  readonly firstBytesKey: string
  readonly length: number
  readonly offsets: Map<string, OffsetStat>
  budgetExceeded: boolean
}

interface FlowState {
  readonly clusters: Map<string, ClusterState>
  budgetExceeded: boolean
}

function hexKey(buf: Uint8Array, offset: number, length: number): string {
  let out = ''
  const end = Math.min(buf.length, offset + length)
  for (let i = offset; i < end; i++) out += buf[i]!.toString(16).padStart(2, '0')
  return out
}

function readUintBE(buf: Uint8Array, offset: number, width: number): number | null {
  if (offset + width > buf.length) return null
  let v = 0
  for (let i = 0; i < width; i++) v = (v << 8) | buf[offset + i]!
  return v >>> 0
}

export class ProprietaryLightSession {
  private readonly flows = new Map<ProprietaryFlowKey, FlowState>()
  private flowOverflow = false

  get overflow(): boolean {
    return this.flowOverflow
  }

  flowKey(input: {
    readonly transport: string
    readonly srcIp: string
    readonly dstIp: string
    readonly srcPort: number
    readonly dstPort: number
  }): ProprietaryFlowKey {
    const a = `${input.srcIp}:${input.srcPort}`
    const b = `${input.dstIp}:${input.dstPort}`
    const left = a < b ? a : b
    const right = a < b ? b : a
    return `${input.transport}|${left}|${right}`
  }

  /**
   * Observe one payload for statistics. Returns whether this cluster is ready
   * for light inference (≥ min messages and within budget).
   */
  observe(input: {
    readonly flowKey: ProprietaryFlowKey
    readonly senderKey: string
    readonly buffer: Uint8Array
    readonly offset: number
    readonly length: number
  }): { ready: boolean; clusterKey: string; budgetExceeded: boolean } {
    const maxScan = Math.min(input.length, PCAP_KERNEL_BUDGETS.proprietaryLightMaxPayloadBytes)
    const head = Math.min(4, maxScan)
    const firstBytesKey = hexKey(input.buffer, input.offset, head)
    const clusterKey = `${input.length}:${firstBytesKey}`

    if (this.flows.size >= PCAP_KERNEL_BUDGETS.proprietaryLightMaxFlows && !this.flows.has(input.flowKey)) {
      this.flowOverflow = true
      return { ready: false, clusterKey, budgetExceeded: true }
    }

    let flow = this.flows.get(input.flowKey)
    if (!flow) {
      flow = { clusters: new Map(), budgetExceeded: false }
      this.flows.set(input.flowKey, flow)
    }
    if (flow.budgetExceeded) {
      return { ready: false, clusterKey, budgetExceeded: true }
    }

    let cluster = flow.clusters.get(clusterKey)
    if (!cluster) {
      if (flow.clusters.size >= PCAP_KERNEL_BUDGETS.proprietaryLightMaxClustersPerFlow) {
        flow.budgetExceeded = true
        return { ready: false, clusterKey, budgetExceeded: true }
      }
      cluster = {
        messageCount: 0,
        firstBytesKey,
        length: input.length,
        offsets: new Map(),
        budgetExceeded: false,
      }
      flow.clusters.set(clusterKey, cluster)
    }

    cluster.messageCount += 1
    this.sampleOffsets(cluster, input.buffer, input.offset, maxScan, input.senderKey)

    const ready =
      !cluster.budgetExceeded
      && !flow.budgetExceeded
      && cluster.messageCount >= PCAP_KERNEL_BUDGETS.proprietaryLightMinClusterMessages
    return { ready, clusterKey, budgetExceeded: cluster.budgetExceeded || flow.budgetExceeded }
  }

  private sampleOffsets(
    cluster: ClusterState,
    buffer: Uint8Array,
    base: number,
    maxScan: number,
    senderKey: string,
  ): void {
    const widths: Array<1 | 2 | 4 | 8> = [1, 2, 4, 8]
    for (const width of widths) {
      for (let rel = 0; rel + width <= maxScan; rel += width) {
        if (cluster.offsets.size >= PCAP_KERNEL_BUDGETS.proprietaryLightMaxOffsetsPerCluster) {
          cluster.budgetExceeded = true
          return
        }
        const key = `${rel}:${width}`
        let stat = cluster.offsets.get(key)
        if (!stat) {
          if (cluster.offsets.size >= PCAP_KERNEL_BUDGETS.proprietaryLightMaxOffsetsPerCluster) {
            cluster.budgetExceeded = true
            return
          }
          stat = {
            width,
            values: new Map(),
            valueSenders: new Map(),
            monoUp: true,
            monoDown: true,
            lastNum: null,
          }
          cluster.offsets.set(key, stat)
        }
        const vk = hexKey(buffer, base + rel, width)
        stat.values.set(vk, (stat.values.get(vk) ?? 0) + 1)
        let senders = stat.valueSenders.get(vk)
        if (!senders) {
          senders = new Set()
          stat.valueSenders.set(vk, senders)
        }
        senders.add(senderKey)

        const num = readUintBE(buffer, base + rel, width)
        if (num !== null && stat.lastNum !== null) {
          if (num < stat.lastNum) stat.monoUp = false
          if (num > stat.lastNum) stat.monoDown = false
        }
        if (num !== null) stat.lastNum = num
      }
    }
  }

  /**
   * Classify sampled offsets for a ready cluster.
   * Sender-bound: value stable per sender, differs across senders.
   */
  classifyOffsets(
    flowKey: ProprietaryFlowKey,
    clusterKey: string,
  ): readonly { rel: number; width: 1 | 2 | 4 | 8; fieldClass: ProprietaryFieldClass }[] {
    const flow = this.flows.get(flowKey)
    const cluster = flow?.clusters.get(clusterKey)
    if (!cluster || cluster.budgetExceeded) return []

    const out: { rel: number; width: 1 | 2 | 4 | 8; fieldClass: ProprietaryFieldClass }[] = []
    for (const [key, stat] of cluster.offsets) {
      const [relStr, widthStr] = key.split(':')
      const rel = Number(relStr)
      const width = Number(widthStr) as 1 | 2 | 4 | 8
      const cardinality = stat.values.size
      let fieldClass: ProprietaryFieldClass = 'unclassified'

      if (cardinality === 1) {
        fieldClass = 'constant'
      } else if ((stat.monoUp || stat.monoDown) && cardinality >= cluster.messageCount * 0.5) {
        fieldClass = 'counter'
      } else {
        // Sender-bound: each value maps to ≤1 sender and ≥2 senders overall.
        let senderBound = true
        const allSenders = new Set<string>()
        for (const senders of stat.valueSenders.values()) {
          if (senders.size !== 1) {
            senderBound = false
            break
          }
          for (const s of senders) allSenders.add(s)
        }
        if (senderBound && allSenders.size >= 2 && cardinality >= 2) {
          fieldClass = 'sender-bound-id'
        }
      }

      if (fieldClass !== 'unclassified') {
        out.push({ rel, width, fieldClass })
      }
    }
    return out
  }
}
