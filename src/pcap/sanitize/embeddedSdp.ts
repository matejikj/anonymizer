/**
 * Shared nested-SDP apply for gateway/control protocols (T24 H.248 / RTSP).
 * Same extract → redact-plan path as MGCP; registers media flows when index given.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import { parseSdp } from '../protocols/application/sdp/parser'
import { extractSdpEntities } from '../protocols/application/sdp/extract'
import { buildSdpRedactionPlan } from '../protocols/application/sdp/redactPlan'
import { DEFAULT_SDP_REDACTION_POLICY } from '../protocols/application/sdp/types'
import { buildSdpMediaEndpoints } from '../protocols/application/sdp/mediaModel'
import { shiftSessionVersion } from '../protocols/application/sdp/sessionVersionShift'
import { resolveIdentityAlias } from '../protocols/application/sip/mappingWire'
import type { PatchCollector } from './PatchCollector'
import type { LayerCoverage } from './types'
import { computeFixedLengthAsciiBytes, patchFixedLengthAscii } from './textPatch'
import { maskPayloadSpan } from '../protocols/application/textproto'
import { deferredSessionVersionMeta } from './deferredMapMeta'

const SDP_MASK = 0x78

export function sanitizeEmbeddedSdpSpan(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
  issues: string[],
  mediaFlowIndex: MediaFlowIndex | undefined,
  callId: string | null,
  protocol: string,
): void {
  void mapping
  if (length < 4) return
  const sdp = parseSdp(buffer, { offset, length })
  if (sdp.kind !== 'complete') {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, `${protocol}-sdp-malformed`)
    coverage.push({ protocol: 'sdp', offset, length, status: 'malformed' })
    issues.push(`${protocol}-sdp-malformed`)
    return
  }

  coverage.push({ protocol: 'sdp', offset, length, status: 'covered' })
  const extracted = extractSdpEntities(sdp.session, buffer, {
    policy: DEFAULT_SDP_REDACTION_POLICY,
  })
  const plan = buildSdpRedactionPlan(extracted.entities, { maskByte: SDP_MASK })
  for (const op of plan.operations) {
    const { offset: abs, length: len } = op.span
    if (len <= 0) continue
    if (op.action === 'redact') {
      patchFixedLengthAscii(collector, abs, len, '', op.maskByte)
      intents?.recordMaskRange(packetIndex, abs, len, `${protocol}-sdp`, 'sdp')
      continue
    }
    if (op.action !== 'map' || !op.mappingCategory) continue
    const original = latin1(buffer, abs, len)
    if (op.sessionIdForVersion !== undefined) {
      const sessionIdOriginal = op.sessionIdForVersion
      collector.addDeferred(
        abs,
        len,
        ({ mapping: live }) => {
          const idAlias = resolveIdentityAlias(
            live, 'sdp-session-id', sessionIdOriginal, 'udp', 'signaling', sessionIdOriginal,
          )
          return computeFixedLengthAsciiBytes(
            abs, len, shiftSessionVersion(original, sessionIdOriginal, idAlias),
          )
        },
        deferredSessionVersionMeta(packetIndex, original, sessionIdOriginal),
      )
      continue
    }
    const category = op.mappingCategory
    const canonical = op.canonicalText
    collector.addDeferred(abs, len, ({ mapping: live }) => {
      const alias = resolveIdentityAlias(live, category, canonical, 'udp', 'signaling', original)
      return computeFixedLengthAsciiBytes(abs, len, alias)
    }, {
      fallbackKind: category === 'port' || category === 'sdp-session-id' ? 'digits' : 'text-x',
      protocol,
      category,
      packetIndex,
    })
  }

  const endpoints = buildSdpMediaEndpoints(sdp.session, buffer, { callId })
  mediaFlowIndex?.registerBundle({ session: sdp.session, endpoints, callId }, buffer)
}

function latin1(buf: Uint8Array, off: number, len: number): string {
  let s = ''
  for (let i = 0; i < len; i++) s += String.fromCharCode(buf[off + i]!)
  return s
}
