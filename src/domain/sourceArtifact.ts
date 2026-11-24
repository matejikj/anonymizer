/**
 * Source kind and artifact descriptors (task-1 §4.4 / Stage 16).
 * Shared contracts for text and PCAP adapters — no React/UI imports.
 */

import { assertNever } from './assertNever.ts'

export const SourceKind = { Text: 'text', Pcap: 'pcap' } as const
export type SourceKind = (typeof SourceKind)[keyof typeof SourceKind]

export interface TextSourceDescriptor {
  readonly fileName: string
  readonly byteLength: number
  readonly lineEnding: 'lf' | 'crlf' | 'cr' | 'mixed' | 'unknown'
}

export interface PcapSourceDescriptor {
  readonly fileName: string
  readonly byteLength: number
  readonly format: 'classic-pcap' | 'pcapng'
}

export type SourceArtifact =
  | { readonly kind: typeof SourceKind.Text; readonly descriptor: TextSourceDescriptor }
  | { readonly kind: typeof SourceKind.Pcap; readonly descriptor: PcapSourceDescriptor }

export function sourceKindLabel(kind: SourceKind): string {
  switch (kind) {
    case SourceKind.Text:
      return 'text'
    case SourceKind.Pcap:
      return 'pcap'
    default:
      return assertNever(kind, 'SourceKind')
  }
}
