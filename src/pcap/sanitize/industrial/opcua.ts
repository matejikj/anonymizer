/**
 * T30 — OPC UA (TCP 4840): HEL/ACK EndpointUrl map; OPN SecurityMode + secret mask; MSG Sign plaintext walk.
 */

import type { PatchCollector } from '../PatchCollector.ts'
import type { MappingLike } from '../../anonymization/mapping.ts'
import type { IntentCollector } from '../../discovery/intentCollector.ts'
import type { AppLayerResult } from '../types.ts'
import type { ApplicationFlowEndpoint } from '../applicationDispatchTypes.ts'
import { decodeAscii, mapAsciiIdentity, maskBytes } from './common.ts'
import {
  type OpcuaChannelSession,
  opcuaSecurityModeFromWire,
} from './opcuaChannelSession.ts'
import {
  readOpenSecureChannelSecurityMode,
  readUaByteStringSpan,
  readUaExtensionObject,
  readUaI32,
  readUaNodeId,
  readUaRequestHeader,
  readUaStringSpan,
} from './opcuaUaBinary.ts'

export const OPCUA_TCP_PORT = 4840

export interface OpcuaSanitizeContext {
  readonly flowEndpoint?: ApplicationFlowEndpoint | null
  readonly opcuaChannel?: OpcuaChannelSession
}

export function isOpcuaPortHint(src: number, dst: number): boolean {
  return src === OPCUA_TCP_PORT || dst === OPCUA_TCP_PORT
}

export function looksLikeOpcua(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 8) return false
  const msg = decodeAscii(buffer, offset, 3)
  return msg === 'HEL' || msg === 'ACK' || msg === 'ERR' || msg === 'OPN' || msg === 'MSG' || msg === 'CLO'
}

export function sanitizeOpcua(
  buffer: Uint8Array,
  offset: number,
  length: number,
  srcPort: number,
  dstPort: number,
  collector: PatchCollector,
  mapping: MappingLike,
  packetIndex: number,
  _highPrivacy: boolean,
  intents?: IntentCollector,
  ctx?: OpcuaSanitizeContext,
): AppLayerResult | null {
  if (!isOpcuaPortHint(srcPort, dstPort) && !looksLikeOpcua(buffer, offset, length)) {
    return null
  }

  const flowKey = ctx?.opcuaChannel?.flowKey(ctx.flowEndpoint ?? null, srcPort, dstPort)

  const coverage: AppLayerResult['coverage'] = []
  const issues: string[] = []
  const end = offset + length
  let pos = offset

  while (pos + 8 <= end) {
    const msgType = decodeAscii(buffer, pos, 3)
    const isFinal = buffer[pos + 3] === 0x46 // 'F'
    const msgSize = (
      buffer[pos + 4]!
      | (buffer[pos + 5]! << 8)
      | (buffer[pos + 6]! << 16)
      | (buffer[pos + 7]! << 24)
    ) >>> 0
    if (msgSize < 8 || pos + msgSize > end) {
      maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-desync', 'opcua')
      coverage.push({
        protocol: 'opcua-body',
        offset: pos,
        length: end - pos,
        status: 'redacted',
      })
      issues.push('opcua-frame-desync')
      break
    }
    coverage.push({ protocol: 'opcua', offset: pos, length: 8, status: 'covered' })
    const bodyOff = pos + 8
    const bodyLen = msgSize - 8

    if (msgType === 'HEL' || msgType === 'ACK') {
      sanitizeHelloAck(
        buffer,
        bodyOff,
        bodyLen,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
      )
    } else if (msgType === 'ERR') {
      if (bodyLen >= 4) {
        coverage.push({ protocol: 'opcua', offset: bodyOff, length: 4, status: 'covered' })
        if (bodyLen > 4) {
          maskBytes(
            collector,
            intents,
            packetIndex,
            bodyOff + 4,
            bodyLen - 4,
            'opcua-error',
            'opcua',
          )
          coverage.push({
            protocol: 'opcua-body',
            offset: bodyOff + 4,
            length: bodyLen - 4,
            status: 'redacted',
          })
        }
      }
    } else if (msgType === 'OPN') {
      sanitizeOpenSecureChannel(
        buffer,
        bodyOff,
        bodyLen,
        collector,
        intents,
        packetIndex,
        coverage,
        issues,
        ctx?.opcuaChannel,
        flowKey,
      )
    } else if (msgType === 'MSG') {
      const mode = flowKey && ctx?.opcuaChannel ? ctx.opcuaChannel.getSecurityMode(flowKey) : 'unknown'
      sanitizeSecureMessage(
        buffer,
        bodyOff,
        bodyLen,
        mode,
        collector,
        mapping,
        intents,
        packetIndex,
        coverage,
        issues,
      )
    } else if (msgType === 'CLO') {
      if (bodyLen > 0) {
        coverage.push({ protocol: 'opcua', offset: bodyOff, length: bodyLen, status: 'covered' })
      }
    } else {
      maskBytes(collector, intents, packetIndex, bodyOff, bodyLen, 'opcua-unknown', 'opcua')
      coverage.push({
        protocol: 'opcua-body',
        offset: bodyOff,
        length: bodyLen,
        status: 'redacted',
      })
    }

    void isFinal
    pos += msgSize
  }

  if (coverage.length === 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'opcua-session', 'opcua')
    coverage.push({ protocol: 'opcua', offset, length, status: 'redacted' })
  }

  return { coverage, issues }
}

function sanitizeOpenSecureChannel(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
  session: OpcuaChannelSession | undefined,
  flowKey: string | undefined,
): void {
  const end = offset + length
  let pos = offset
  const channelId = readUaI32(buffer, pos, end)
  if (!channelId) {
    maskBytes(collector, intents, packetIndex, offset, length, 'opcua-opn', 'opcua')
    coverage.push({ protocol: 'opcua-auth', offset, length, status: 'redacted' })
    issues.push('opcua-opn-truncated')
    return
  }
  coverage.push({ protocol: 'opcua', offset: pos, length: 4, status: 'covered' })
  pos = channelId.next

  const policyUri = readUaStringSpan(buffer, pos, end)
  if (!policyUri) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-opn', 'opcua')
    issues.push('opcua-opn-truncated')
    return
  }
  coverage.push({
    protocol: 'opcua',
    offset: pos,
    length: policyUri.next - pos,
    status: 'covered',
  })
  pos = policyUri.next

  const senderCert = readUaByteStringSpan(buffer, pos, end)
  if (!senderCert) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-opn', 'opcua')
    issues.push('opcua-opn-truncated')
    return
  }
  if (senderCert.byteLength > 0) {
    maskBytes(
      collector,
      intents,
      packetIndex,
      senderCert.dataOffset,
      senderCert.byteLength,
      'opcua-cert',
      'opcua',
    )
    coverage.push({
      protocol: 'opcua-auth',
      offset: senderCert.dataOffset,
      length: senderCert.byteLength,
      status: 'redacted',
    })
  }
  pos = senderCert.next

  const thumb = readUaByteStringSpan(buffer, pos, end)
  if (!thumb) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-opn', 'opcua')
    issues.push('opcua-opn-truncated')
    return
  }
  if (thumb.byteLength > 0) {
    maskBytes(
      collector,
      intents,
      packetIndex,
      thumb.dataOffset,
      thumb.byteLength,
      'opcua-cert',
      'opcua',
    )
    coverage.push({
      protocol: 'opcua-auth',
      offset: thumb.dataOffset,
      length: thumb.byteLength,
      status: 'redacted',
    })
  }
  pos = thumb.next

  if (pos + 8 > end) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-opn', 'opcua')
    issues.push('opcua-opn-truncated')
    return
  }
  coverage.push({ protocol: 'opcua', offset: pos, length: 8, status: 'covered' })
  pos += 8

  const extBodyStart = pos
  const ext = readUaExtensionObject(buffer, pos, end)
  if (!ext) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-opn', 'opcua')
    issues.push('opcua-opn-truncated')
    return
  }

  const modeWire = extractOpenSecureChannelSecurityMode(buffer, extBodyStart, ext.next)
  if (modeWire !== null && session && flowKey) {
    session.setSecurityMode(flowKey, opcuaSecurityModeFromWire(modeWire))
    issues.push('opcua-opn-security-mode')
  }

  const nonce = findOpenSecureChannelClientNonce(buffer, extBodyStart, ext.next)
  if (nonce && nonce.byteLength > 0) {
    maskBytes(
      collector,
      intents,
      packetIndex,
      nonce.dataOffset,
      nonce.byteLength,
      'opcua-nonce',
      'opcua',
    )
    coverage.push({
      protocol: 'opcua-auth',
      offset: nonce.dataOffset,
      length: nonce.byteLength,
      status: 'redacted',
    })
  }

  coverage.push({
    protocol: 'opcua-auth',
    offset: extBodyStart,
    length: ext.next - extBodyStart,
    status: 'redacted',
  })
  if (ext.next < end) {
    maskBytes(collector, intents, packetIndex, ext.next, end - ext.next, 'opcua-opn', 'opcua')
  }
  issues.push('opcua-opn-parsed')
}

function extractOpenSecureChannelSecurityMode(
  buffer: Uint8Array,
  offset: number,
  end: number,
): number | null {
  const typeId = readUaNodeId(buffer, offset, end)
  if (!typeId) return null
  let pos = typeId.next
  if (pos >= end || buffer[pos] !== 1) return null
  pos += 1
  const bodyLenField = readUaI32(buffer, pos, end)
  if (!bodyLenField || bodyLenField.value < 12) return null
  const bodyEnd = bodyLenField.next + bodyLenField.value
  if (bodyEnd > end) return null
  const mode = readOpenSecureChannelSecurityMode(buffer, bodyLenField.next, bodyEnd)
  return mode ? mode.securityMode : null
}

function findOpenSecureChannelClientNonce(
  buffer: Uint8Array,
  offset: number,
  end: number,
): { dataOffset: number; byteLength: number } | null {
  const typeId = readUaNodeId(buffer, offset, end)
  if (!typeId) return null
  let pos = typeId.next
  if (pos >= end || buffer[pos] !== 1) return null
  pos += 1
  const bodyLenField = readUaI32(buffer, pos, end)
  if (!bodyLenField || bodyLenField.value < 12) return null
  const nonceOff = bodyLenField.next + 12
  const span = readUaByteStringSpan(buffer, nonceOff, end)
  if (!span) return null
  return { dataOffset: span.dataOffset, byteLength: span.byteLength }
}

function sanitizeSecureMessage(
  buffer: Uint8Array,
  offset: number,
  length: number,
  securityMode: import('./opcuaChannelSession.ts').OpcuaSecurityMode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): void {
  const end = offset + length
  if (length < 16) {
    maskBytes(collector, intents, packetIndex, offset, length, 'opcua-msg', 'opcua')
    coverage.push({ protocol: 'opcua-body', offset, length, status: 'redacted' })
    issues.push('opcua-msg-truncated')
    return
  }

  coverage.push({ protocol: 'opcua', offset, length: 16, status: 'covered' })
  let pos = offset + 16

  if (securityMode === 'sign-and-encrypt') {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-msg', 'opcua')
    coverage.push({
      protocol: 'opcua-body',
      offset: pos,
      length: end - pos,
      status: 'redacted',
    })
    issues.push('opcua-msg-encrypted')
    return
  }

  if (securityMode === 'unknown') {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-msg', 'opcua')
    coverage.push({
      protocol: 'opcua-body',
      offset: pos,
      length: end - pos,
      status: 'redacted',
    })
    issues.push('opcua-msg-security-unknown')
    return
  }

  if (pos + 8 <= end) {
    coverage.push({ protocol: 'opcua', offset: pos, length: 8, status: 'covered' })
    pos += 8
  }

  const parsed = sanitizeUaBinaryServiceBody(
    buffer,
    pos,
    end,
    collector,
    mapping,
    intents,
    packetIndex,
    coverage,
    issues,
  )
  if (parsed < end) {
    coverage.push({
      protocol: 'opcua',
      offset: parsed,
      length: end - parsed,
      status: 'covered',
    })
  }
  issues.push(securityMode === 'sign' ? 'opcua-msg-sign-plaintext' : 'opcua-msg-none-plaintext')
}

function sanitizeUaBinaryServiceBody(
  buffer: Uint8Array,
  offset: number,
  end: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
  issues: string[],
): number {
  let pos = offset
  const typeId = readUaNodeId(buffer, pos, end)
  if (!typeId) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-msg', 'opcua')
    coverage.push({ protocol: 'opcua-body', offset: pos, length: end - pos, status: 'redacted' })
    issues.push('opcua-binary-walk-truncated')
    return end
  }
  coverage.push({ protocol: 'opcua', offset: pos, length: typeId.next - pos, status: 'covered' })
  pos = typeId.next

  const header = readUaRequestHeader(buffer, pos, end)
  if (!header) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-msg', 'opcua')
    coverage.push({ protocol: 'opcua-body', offset: pos, length: end - pos, status: 'redacted' })
    issues.push('opcua-binary-walk-truncated')
    return end
  }
  coverage.push({
    protocol: 'opcua',
    offset: pos,
    length: header.next - pos,
    status: 'covered',
  })
  if (header.auditEntryId && header.auditEntryId.byteLength > 0) {
    mapAsciiIdentity(
      buffer,
      header.auditEntryId.dataOffset,
      header.auditEntryId.byteLength,
      'opaque-id',
      collector,
      mapping,
      intents,
      packetIndex,
      'opcua',
    )
    coverage.push({
      protocol: 'opcua-body',
      offset: header.auditEntryId.dataOffset,
      length: header.auditEntryId.byteLength,
      status: 'covered',
    })
  }
  pos = header.next

  if (pos < end) {
    maskBytes(collector, intents, packetIndex, pos, end - pos, 'opcua-msg-body', 'opcua')
    coverage.push({
      protocol: 'opcua-body',
      offset: pos,
      length: end - pos,
      status: 'redacted',
    })
  }
  return end
}

function sanitizeHelloAck(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  if (length < 20) {
    maskBytes(collector, intents, packetIndex, offset, length, 'opcua-hel', 'opcua')
    coverage.push({ protocol: 'opcua-body', offset, length, status: 'redacted' })
    return
  }
  coverage.push({ protocol: 'opcua', offset, length: 20, status: 'covered' })
  if (length < 24) return
  const strLen =
    (buffer[offset + 20]!
      | (buffer[offset + 21]! << 8)
      | (buffer[offset + 22]! << 16)
      | (buffer[offset + 23]! << 24)) >> 0
  if (strLen <= 0 || 24 + strLen > length) {
    if (strLen === -1) {
      coverage.push({ protocol: 'opcua', offset: offset + 20, length: 4, status: 'covered' })
    }
    return
  }
  coverage.push({ protocol: 'opcua', offset: offset + 20, length: 4, status: 'covered' })
  const urlOff = offset + 24
  sanitizeEndpointUrl(buffer, urlOff, strLen, collector, mapping, intents, packetIndex, coverage)
}

function sanitizeEndpointUrl(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  coverage: AppLayerResult['coverage'],
): void {
  const text = decodeAscii(buffer, offset, length)
  const scheme = 'opc.tcp://'
  const schemeIdx = text.toLowerCase().indexOf('opc.tcp://')
  if (schemeIdx < 0) {
    maskBytes(collector, intents, packetIndex, offset, length, 'opcua-url', 'opcua')
    coverage.push({ protocol: 'opcua-url', offset, length, status: 'redacted' })
    return
  }
  const hostStart = offset + schemeIdx + scheme.length
  let hostEnd = hostStart
  const end = offset + length
  while (hostEnd < end && buffer[hostEnd] !== 0x3a && buffer[hostEnd] !== 0x2f) hostEnd++
  if (hostEnd > hostStart) {
    mapAsciiIdentity(
      buffer,
      hostStart,
      hostEnd - hostStart,
      'hostname',
      collector,
      mapping,
      intents,
      packetIndex,
      'opcua',
    )
    coverage.push({
      protocol: 'opcua-url',
      offset: hostStart,
      length: hostEnd - hostStart,
      status: 'covered',
    })
  }
  let p = hostEnd
  if (p < end && buffer[p] === 0x3a) {
    p++
    while (p < end && buffer[p]! >= 0x30 && buffer[p]! <= 0x39) p++
    coverage.push({
      protocol: 'opcua',
      offset: hostEnd,
      length: p - hostEnd,
      status: 'covered',
    })
  }
  if (p < end) {
    maskBytes(collector, intents, packetIndex, p, end - p, 'opcua-path', 'opcua')
    coverage.push({
      protocol: 'opcua-url',
      offset: p,
      length: end - p,
      status: 'redacted',
    })
  }
}
