/**
 * T24 — RTSP 1.0 (TCP 554/8554): URI/host/port map, Session opaque, Transport media ports,
 * Authorization mask, application/sdp body → nested SDP + media flows. Interleaved `$` → mask.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { MediaFlowIndex } from '../discovery/mediaFlowIndex'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import {
  tokenizeTextProtoMessage,
  dispositionForTextProtoHeader,
  applyPayloadMapHits,
  hitsFromExtractors,
  hitsFromDetectors,
  detectIdentitiesInPayload,
  maskPayloadSpan,
  extractTextProtoValues,
  type TextProtoHeaderPolicyTable,
} from '../protocols/application/textproto'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { createProtocolNeutralMaskFill } from './maskFill'
import { sanitizeEmbeddedSdpSpan } from './embeddedSdp'

const RTSP_PORTS = new Set([554, 8554])

export const RTSP_HEADER_POLICY: TextProtoHeaderPolicyTable = {
  protocolId: 'rtsp',
  entries: [
    { name: 'cseq', action: { kind: 'structural' } },
    { name: 'public', action: { kind: 'preserve' } },
    { name: 'scale', action: { kind: 'structural' } },
    { name: 'range', action: { kind: 'preserve' } }, // NPT/SMPTE preserve; clock= handled below
    { name: 'session', action: { kind: 'map', category: 'opaque-id' } },
    { name: 'transport', action: { kind: 'detectors' } },
    { name: 'content-type', action: { kind: 'structural' } },
    { name: 'content-length', action: { kind: 'structural' } },
    { name: 'authorization', action: { kind: 'credential' } },
    { name: 'www-authenticate', action: { kind: 'credential' } },
    { name: 'user-agent', action: { kind: 'mask' } },
    { name: 'server', action: { kind: 'mask' } },
  ],
  defaultAction: { kind: 'mask' },
}

export function isRtspPortHint(src: number, dst: number): boolean {
  return RTSP_PORTS.has(src) || RTSP_PORTS.has(dst)
}

export function looksLikeRtsp(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  // Interleaved binary frame
  if (data[offset] === 0x24 && length >= 4) return true
  const head = latin1(data, offset, Math.min(length, 64))
  return /^(?:OPTIONS|DESCRIBE|ANNOUNCE|SETUP|PLAY|PAUSE|TEARDOWN|GET_PARAMETER|SET_PARAMETER|REDIRECT|RECORD)\s/i.test(head)
    || /^RTSP\/1\.[01]\s+\d{3}/i.test(head)
}

export function sanitizeRtsp(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  mediaFlowIndex?: MediaFlowIndex,
): AppLayerResult | null {
  if (!looksLikeRtsp(buffer, offset, length)) return null

  // Interleaved RTP/RTCP: $ <ch> <len16be> <payload>
  if (buffer[offset] === 0x24) {
    return sanitizeInterleaved(buffer, offset, length, collector, mapping, intents, packetIndex)
  }

  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const msg = tokenizeTextProtoMessage(buffer, offset, length)
  if (!msg) {
    maskPayloadSpan(collector, offset, length, intents, packetIndex, 'rtsp-parse')
    return {
      coverage: [{ protocol: 'rtsp', offset, length, status: 'malformed' }],
      issues: ['rtsp-parse'],
    }
  }

  // Request-line URI / response start
  const startHits = hitsFromExtractors(extractTextProtoValues(msg.startLineText, offset))
  applyPayloadMapHits(startHits, collector, mapping, intents, packetIndex, 'rtsp')

  for (const h of msg.headers) {
    const action = dispositionForTextProtoHeader(RTSP_HEADER_POLICY, h.name)
    const abs = h.valueSpan.offset
    const len = h.valueSpan.length
    if (len <= 0) continue

    if (h.name === 'transport') {
      sanitizeTransport(h.valueText, abs, collector, mapping, intents, packetIndex, coverage)
      continue
    }
    if (h.name === 'range' && /clock=/i.test(h.valueText)) {
      // Absolute clock → mask time token (Δ handled later via T14 payloadTime when wired)
      const clock = /clock=([^\s;]+)/i.exec(h.valueText)
      if (clock) {
        const idx = h.valueText.indexOf(clock[1]!)
        maskPayloadSpan(collector, abs + idx, clock[1]!.length, intents, packetIndex, 'rtsp-clock')
      }
      coverage.push({ protocol: 'rtsp-range', offset: abs, length: len, status: 'covered' })
      continue
    }

    switch (action.kind) {
      case 'preserve':
      case 'structural':
        break
      case 'mask':
      case 'credential':
        maskPayloadSpan(collector, abs, len, intents, packetIndex, `rtsp-${h.name}`)
        coverage.push({ protocol: 'rtsp-auth', offset: abs, length: len, status: 'redacted' })
        break
      case 'map': {
        const canon = canonicalizeIdentity(action.category, h.valueText.trim()) ?? h.valueText.trim()
        const constraint = { kind: 'text-ascii' as const, byteLength: len }
        intents?.recordEntityReplacement(packetIndex, abs, action.category, canon, len, constraint, h.valueText)
        collector.addDeferred(abs, len, ({ mapping: live }) => {
          try {
            return computeFixedLengthAsciiBytes(abs, len, live.aliasFor(action.category, canon, constraint, h.valueText))
          } catch {
            return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: 'rtsp-session' })
          }
        }, { fallbackKind: 'text-x', protocol: 'rtsp', category: action.category, packetIndex })
        break
      }
      case 'detectors': {
        const det = detectIdentitiesInPayload(buffer, abs, len)
        applyPayloadMapHits(hitsFromDetectors(det), collector, mapping, intents, packetIndex, 'rtsp')
        break
      }
      default:
        maskPayloadSpan(collector, abs, len, intents, packetIndex, `rtsp-${h.name}`)
    }
  }

  if (msg.body && msg.body.length > 0) {
    const ct = msg.headers.find((h) => h.name === 'content-type')?.valueText.toLowerCase() ?? ''
    if (ct.includes('application/sdp') || latin1(buffer, msg.body.offset, Math.min(3, msg.body.length)) === 'v=0') {
      sanitizeEmbeddedSdpSpan(
        buffer, msg.body.offset, msg.body.length, collector, mapping, intents, packetIndex,
        coverage, issues, mediaFlowIndex, null, 'rtsp',
      )
    } else {
      maskPayloadSpan(
        collector, msg.body.offset, msg.body.length, intents, packetIndex, 'rtsp-body',
      )
      coverage.push({
        protocol: 'rtsp-body',
        offset: msg.body.offset,
        length: msg.body.length,
        status: 'redacted',
      })
    }
  }

  coverage.unshift({ protocol: 'rtsp', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeInterleaved(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult {
  void mapping
  const coverage: LayerCoverage[] = []
  let pos = offset
  const end = offset + length
  while (pos + 4 <= end && buffer[pos] === 0x24) {
    const channel = buffer[pos + 1]!
    const frameLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    coverage.push({ protocol: 'rtsp-interleaved', offset: pos, length: 4, status: 'covered' })
    const payOff = pos + 4
    const payLen = Math.min(frameLen, end - payOff)
    if (payLen > 0) {
      // Channel alone does not prove RTP vs RTCP — mask payload fail-closed
      maskPayloadSpan(collector, payOff, payLen, intents, packetIndex, `rtsp-ch-${channel}`)
      coverage.push({ protocol: 'rtsp-media', offset: payOff, length: payLen, status: 'redacted' })
    }
    pos = payOff + frameLen
    if (frameLen < 0) break
  }
  if (pos < end) {
    maskPayloadSpan(collector, pos, end - pos, intents, packetIndex, 'rtsp-interleaved-tail')
    coverage.push({ protocol: 'rtsp', offset: pos, length: end - pos, status: 'redacted' })
  }
  coverage.unshift({ protocol: 'rtsp', offset, length, status: 'covered' })
  return { coverage }
}

function sanitizeTransport(
  value: string,
  abs: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: LayerCoverage[],
): void {
  // client_port=x-y; server_port=; destination=; source=; ssrc=
  const re = /\b((?:client_port|server_port|destination|source|ssrc)=)([^;\s]+)/gi
  let m: RegExpExecArray | null
  while ((m = re.exec(value)) !== null) {
    const key = m[1]!.toLowerCase()
    const val = m[2]!
    const valAbs = abs + m.index + m[1]!.length
    if (key.startsWith('ssrc=')) {
      // SSRC — map as opaque via existing ssrc category if available, else mask
      const canon = canonicalizeIdentity('ssrc', val)
      if (canon) {
        const constraint = { kind: 'text-ascii' as const, byteLength: val.length }
        intents?.recordEntityReplacement(packetIndex, valAbs, 'ssrc', canon, val.length, constraint, val)
        collector.addDeferred(valAbs, val.length, ({ mapping: live }) => {
          try {
            return computeFixedLengthAsciiBytes(valAbs, val.length, live.aliasFor('ssrc', canon, constraint, val))
          } catch {
            return createProtocolNeutralMaskFill({ length: val.length, packetIndex, offset: valAbs, domain: 'rtsp-ssrc' })
          }
        }, { fallbackKind: 'digits', protocol: 'rtsp', category: 'ssrc', packetIndex })
      } else {
        maskPayloadSpan(collector, valAbs, val.length, intents, packetIndex, 'rtsp-ssrc')
      }
      continue
    }
    if (key.includes('port')) {
      // port or port-port
      const parts = val.split('-')
      let cursor = 0
      for (const p of parts) {
        const canon = canonicalizeIdentity('port', `udp/${p}`)
        if (canon) {
          const constraint = { kind: 'text-ascii' as const, byteLength: p.length }
          intents?.recordEntityReplacement(packetIndex, valAbs + cursor, 'port', canon, p.length, constraint, p)
          const off = valAbs + cursor
          collector.addDeferred(off, p.length, ({ mapping: live }) => {
            try {
              const mapped = live.map('port', canon)
              const slash = mapped.indexOf('/')
              let n = mapped.slice(slash + 1)
              if (n.length > p.length) {
                return createProtocolNeutralMaskFill({ length: p.length, packetIndex, offset: off, domain: 'rtsp-port' })
              }
              n = n.padStart(p.length, '0')
              return computeFixedLengthAsciiBytes(off, p.length, n)
            } catch {
              return createProtocolNeutralMaskFill({ length: p.length, packetIndex, offset: off, domain: 'rtsp-port' })
            }
          }, { fallbackKind: 'digits', protocol: 'rtsp', category: 'port', packetIndex })
        }
        cursor += p.length + 1
      }
      continue
    }
    // destination/source IP or host
    const hits = hitsFromExtractors(extractTextProtoValues(val, valAbs))
    applyPayloadMapHits(hits, collector, mapping, intents, packetIndex, 'rtsp')
  }
  coverage.push({ protocol: 'rtsp-transport', offset: abs, length: value.length, status: 'covered' })
  void mapping
}

function latin1(buf: Uint8Array, off: number, len: number): string {
  let s = ''
  for (let i = 0; i < len; i++) s += String.fromCharCode(buf[off + i]!)
  return s
}
