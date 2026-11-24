/**
 * Apply MGCP analyze plan via length-preserving patches (T11).
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector.ts'
import { patchFixedLengthAscii, computeFixedLengthAsciiBytes } from '../../../sanitize/textPatch.ts'
import type { MappingLike } from '../../../anonymization/mapping.ts'
import { resolveIdentityAlias } from '../sip/mappingWire.ts'
import { shiftSessionVersion } from '../sdp/sessionVersionShift.ts'
import { sdpSessionIdDigits } from '../../../../mapping/pcapCanonical.ts'
import { deferredSessionVersionMeta } from '../../../sanitize/deferredMapMeta.ts'
import { analyzeMgcpMessages, type MgcpOperation } from './analyze.ts'
import type { MgcpMessage } from './types.ts'

function decodeLatin1Span(buffer: Uint8Array, span: { offset: number; length: number }): string {
  let s = ''
  for (let i = 0; i < span.length; i++) s += String.fromCharCode(buffer[span.offset + i]!)
  return s
}

export function applyMgcpPlan(
  plan: readonly MgcpOperation[],
  buffer: Uint8Array,
  transport: 'tcp' | 'udp',
  collector: PatchCollector,
  packetIndex = 0,
): void {
  for (const op of plan) {
    const { offset, length } = op.span
    if (length <= 0) continue

    if (op.action === 'redact') {
      const mask = String.fromCharCode(op.maskByte).repeat(length)
      patchFixedLengthAscii(collector, offset, length, mask, op.maskByte)
      continue
    }

    if (op.action !== 'map') continue
    const originalSpelling = decodeLatin1Span(buffer, op.span)

    if (op.sessionIdForVersion !== undefined) {
      const sessionIdCanonical = op.sessionIdForVersion
      const versionOriginal = originalSpelling
      collector.addDeferred(
        offset,
        length,
        ({ mapping: liveMapping }) => {
          const sessionIdDigits = sdpSessionIdDigits(sessionIdCanonical)
          const idAlias = resolveIdentityAlias(
            liveMapping,
            'sdp-session-id',
            sessionIdCanonical,
            transport,
            'signaling',
            sessionIdDigits,
          )
          const shifted = shiftSessionVersion(versionOriginal, sessionIdDigits, idAlias)
          return computeFixedLengthAsciiBytes(offset, length, shifted)
        },
        deferredSessionVersionMeta(packetIndex, versionOriginal, sessionIdCanonical),
      )
      continue
    }

    if (op.mappingCategory === null) continue
    const mappingCategory = op.mappingCategory
    const canonicalText = op.canonicalText
    collector.addDeferred(
      offset,
      length,
      ({ mapping: liveMapping }) => {
        const alias = resolveIdentityAlias(
          liveMapping,
          mappingCategory,
          canonicalText,
          transport,
          'signaling',
          originalSpelling,
        )
        return computeFixedLengthAsciiBytes(offset, length, alias)
      },
      {
        fallbackKind:
          mappingCategory === 'port' || mappingCategory === 'sdp-session-id' ? 'digits' : 'text-x',
        protocol: 'mgcp',
        category: mappingCategory,
        packetIndex,
      },
    )
  }
}

export function sanitizeMgcpMessages(
  buffer: Uint8Array,
  messages: readonly MgcpMessage[],
  transport: 'tcp' | 'udp',
  collector: PatchCollector,
  _mapping: MappingLike,
  packetIndex = 0,
): ReturnType<typeof analyzeMgcpMessages> {
  const analyzed = analyzeMgcpMessages(buffer, messages)
  applyMgcpPlan(analyzed.operations, buffer, transport, collector, packetIndex)
  return analyzed
}
