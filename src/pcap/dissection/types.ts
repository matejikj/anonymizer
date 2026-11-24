/**
 * Serializable dissection tree for Wireshark-like UI (step 2).
 */

import type { CoverageStatus } from '../sanitize/types'

export type DissectionChangeKind =
  | 'mapped'
  | 'redacted'
  | 'masked'
  | 'preserved-for-diagnostics'
  | 'rewritten'
  | 'truncated'
  | 'uncovered'
  | 'none'

export interface DissectionNode {
  readonly id: string
  readonly label: string
  readonly fieldName?: string
  readonly value?: string
  readonly displayValue?: string
  readonly offset: number
  readonly length: number
  readonly generated?: boolean
  readonly linkPacketIndex?: number
  readonly coverageStatus?: CoverageStatus
  readonly changeKind?: DissectionChangeKind
  readonly children: readonly DissectionNode[]
}

export interface ByteSource {
  readonly id: string
  readonly label: string
  readonly bytes: Uint8Array
  readonly fieldMap: readonly DissectionNode[]
}

export interface PacketDissection {
  readonly roots: readonly DissectionNode[]
  readonly sources: readonly ByteSource[]
}

export function flattenDissection(nodes: readonly DissectionNode[]): DissectionNode[] {
  const out: DissectionNode[] = []
  const walk = (list: readonly DissectionNode[]) => {
    for (const n of list) {
      out.push(n)
      walk(n.children)
    }
  }
  walk(nodes)
  return out
}

export function findDeepestNodeAtOffset(
  nodes: readonly DissectionNode[],
  offset: number,
): DissectionNode | null {
  let best: DissectionNode | null = null
  let bestLen = Infinity
  const walk = (list: readonly DissectionNode[]) => {
    for (const n of list) {
      if (offset >= n.offset && offset < n.offset + n.length) {
        if (n.length <= bestLen) {
          best = n
          bestLen = n.length
        }
        walk(n.children)
      }
    }
  }
  walk(nodes)
  return best
}

export function nodePath(node: DissectionNode, roots: readonly DissectionNode[]): string | null {
  const target = node
  let found: string | null = null
  const walk = (list: readonly DissectionNode[], prefix: string): boolean => {
    for (const n of list) {
      const path = prefix ? `${prefix}/${n.id}` : n.id
      if (n === target) { found = path; return true }
      if (walk(n.children, path)) return true
    }
    return false
  }
  walk(roots, '')
  return found
}

export function nodeByPath(roots: readonly DissectionNode[], path: string): DissectionNode | null {
  const parts = path.split('/').filter(Boolean)
  let current: readonly DissectionNode[] = roots
  let node: DissectionNode | null = null
  for (const part of parts) {
    node = current.find((n) => n.id === part) ?? null
    if (!node) return null
    current = node.children
  }
  return node
}
