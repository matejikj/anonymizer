/**
 * MGCP sanitizer facade — orchestration over parse / analyze / apply (T11).
 */

import { PatchCollector } from './PatchCollector.ts'
import type { MappingLike } from '../anonymization/mapping.ts'
import { classifyMgcpPayload } from '../protocols/application/mgcp/parse.ts'
import { sanitizeMgcpMessages } from '../protocols/application/mgcp/apply.ts'
import type { MgcpMessage } from '../protocols/application/mgcp/types.ts'
import type { MgcpAnalyzeResult } from '../protocols/application/mgcp/analyze.ts'

export function sanitizeMgcpMessageBatch(
  buffer: Uint8Array,
  messages: readonly MgcpMessage[],
  transport: 'tcp' | 'udp',
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex = 0,
): MgcpAnalyzeResult {
  return sanitizeMgcpMessages(buffer, messages, transport, collector, mapping, packetIndex)
}

export function sanitizeMgcp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  transport: 'tcp' | 'udp' = 'udp',
  packetIndex = 0,
): boolean {
  const classification = classifyMgcpPayload(buffer, offset, length, { portHint: true })
  if (classification.kind !== 'complete') return false
  sanitizeMgcpMessages(buffer, classification.messages, transport, collector, mapping, packetIndex)
  return true
}
