/**
 * T39 — VNC/RFB (TCP 5900–5909): version preserve; DES challenge/response mask;
 * desktop name map; framebuffer/clipboard/key payload fail-closed mask.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import { mapAsciiIdentity, maskBytes, readU32be } from './common.ts'

export const VNC_PORT_MIN = 5900
export const VNC_PORT_MAX = 5909

export function isVncPortHint(srcPort: number, dstPort: number): boolean {
  return (
    (srcPort >= VNC_PORT_MIN && srcPort <= VNC_PORT_MAX)
    || (dstPort >= VNC_PORT_MIN && dstPort <= VNC_PORT_MAX)
  )
}

export function looksLikeVnc(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 12) return false
  return (
    buffer[offset] === 0x52
    && buffer[offset + 1] === 0x46
    && buffer[offset + 2] === 0x42
    && buffer[offset + 3] === 0x20
  )
}

export function sanitizeVnc(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  intents?: IntentCollector,
): AppLayerResult | null {
  if (!isVncPortHint(srcPort, dstPort) && !looksLikeVnc(buffer, offset, length)) return null

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length

  if (!looksLikeVnc(buffer, offset, length)) {
    maskBytes(collector, intents, packetIndex, offset, length, 'vnc-session', 'vnc')
    coverage.push({ protocol: 'vnc', offset, length, status: 'redacted' })
    issues.push('vnc-mid-session-masked')
    return { coverage, issues }
  }

  let pos = offset
  while (pos < end && buffer[pos] !== 0x0a) pos++
  if (pos < end) pos++
  coverage.push({ protocol: 'vnc', offset, length: Math.min(pos - offset, length), status: 'covered' })

  if (pos >= end) return { coverage, issues }

  if (pos + 1 <= end) {
    const nTypes = buffer[pos]!
    if (nTypes > 0 && nTypes < 32 && pos + 1 + nTypes <= end) {
      coverage.push({
        protocol: 'vnc-security',
        offset: pos,
        length: 1 + nTypes,
        status: 'covered',
      })
      pos += 1 + nTypes
    } else if (pos + 4 <= end) {
      coverage.push({ protocol: 'vnc-security', offset: pos, length: 4, status: 'covered' })
      pos += 4
    }
  }

  while (pos + 16 <= end) {
    if (pos + 24 <= end) {
      const nameLen = readU32be(buffer, pos + 20)
      if (nameLen <= 256 && pos + 24 + nameLen <= end) {
        coverage.push({ protocol: 'vnc-serverinit', offset: pos, length: 24, status: 'covered' })
        if (nameLen > 0) {
          mapAsciiIdentity(
            buffer,
            pos + 24,
            nameLen,
            'hostname',
            collector,
            mapping,
            intents,
            packetIndex,
            'vnc',
          )
          coverage.push({
            protocol: 'vnc-desktop-name',
            offset: pos + 24,
            length: nameLen,
            status: 'covered',
          })
        }
        pos += 24 + nameLen
        break
      }
    }
    maskBytes(collector, intents, packetIndex, pos, 16, 'vnc-auth', 'vnc')
    coverage.push({ protocol: 'vnc-auth', offset: pos, length: 16, status: 'redacted' })
    pos += 16
  }

  if (pos < end) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'vnc-content', 'vnc')
    coverage.push({
      protocol: 'vnc-content',
      offset: pos,
      length: end - pos,
      status: 'redacted',
    })
    issues.push('vnc-framebuffer-clipboard-keys-masked')
  }

  coverage.push({ protocol: 'vnc', offset, length, status: 'covered' })
  return { coverage, issues }
}
