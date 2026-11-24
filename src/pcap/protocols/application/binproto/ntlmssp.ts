/**
 * T16 — NTLMSSP (MS-NLMP) parse + sanitize: map identity strings, mask crypto material.
 */

import type { PatchCollector } from '../../../sanitize/PatchCollector'
import type { IntentCollector } from '../../../discovery/intentCollector'
import type { MappingLike } from '../../../anonymization/mapping'
import { createProtocolNeutralMaskFill } from '../../../sanitize/maskFill'
import { SoftCursor } from './softCursor'
import { computeFixedLengthUtf16Bytes, decodeUtf16 } from './utf16'
import { canonicalizeIdentity } from '../../../../mapping/canonicalize'

const NTLM_SIG = new TextEncoder().encode('NTLMSSP\0')

export type NtlmMessageType = 1 | 2 | 3

export interface NtlmSecurityBuffer {
  readonly length: number
  readonly maxLength: number
  readonly offset: number
}

export interface NtlmParseResult {
  readonly messageType: NtlmMessageType
  readonly domain?: NtlmSecurityBuffer
  readonly user?: NtlmSecurityBuffer
  readonly workstation?: NtlmSecurityBuffer
  readonly lmResponse?: NtlmSecurityBuffer
  readonly ntResponse?: NtlmSecurityBuffer
  readonly sessionKey?: NtlmSecurityBuffer
  readonly targetName?: NtlmSecurityBuffer
  readonly targetInfo?: NtlmSecurityBuffer
  readonly negotiateFlags: number
  readonly issues: readonly string[]
}

function readSecBuf(cur: SoftCursor): NtlmSecurityBuffer | null {
  const length = cur.u16(true)
  const maxLength = cur.u16(true)
  const offset = cur.u32(true)
  if (length === null || maxLength === null || offset === null) return null
  return { length, maxLength, offset }
}

function bufInRange(buf: NtlmSecurityBuffer, messageLength: number): boolean {
  if (buf.length === 0) return true
  if (buf.offset > messageLength) return false
  if (buf.offset + buf.length > messageLength) return false
  if (buf.length > 0 && buf.offset < 12) return false
  return true
}

export function looksLikeNtlmssp(
  buffer: Uint8Array,
  offset = 0,
  length = buffer.length - offset,
): boolean {
  if (length < 12) return false
  for (let i = 0; i < 8; i++) {
    if (buffer[offset + i] !== NTLM_SIG[i]) return false
  }
  return true
}

export function parseNtlmssp(
  buffer: Uint8Array,
  absoluteOffset: number,
  byteLength: number,
): NtlmParseResult | null {
  if (!looksLikeNtlmssp(buffer, absoluteOffset, byteLength)) return null
  const cur = new SoftCursor(buffer, absoluteOffset, absoluteOffset + byteLength)
  cur.skip(8)
  const type = cur.u32(true)
  if (type !== 1 && type !== 2 && type !== 3) return null
  const issues: string[] = []

  if (type === 1) {
    const flags = cur.u32(true) ?? 0
    const domain = readSecBuf(cur)
    const workstation = readSecBuf(cur)
    for (const b of [domain, workstation]) {
      if (b && !bufInRange(b, byteLength)) issues.push('ntlm-buffer-oob')
    }
    return {
      messageType: 1,
      domain: domain ?? undefined,
      workstation: workstation ?? undefined,
      negotiateFlags: flags,
      issues,
    }
  }

  if (type === 2) {
    const targetName = readSecBuf(cur)
    const flags = cur.u32(true) ?? 0
    if (!cur.skip(8)) return null
    cur.skip(8)
    const targetInfo = readSecBuf(cur)
    for (const b of [targetName, targetInfo]) {
      if (b && !bufInRange(b, byteLength)) issues.push('ntlm-buffer-oob')
    }
    return {
      messageType: 2,
      targetName: targetName ?? undefined,
      targetInfo: targetInfo ?? undefined,
      negotiateFlags: flags,
      issues,
    }
  }

  const lmResponse = readSecBuf(cur)
  const ntResponse = readSecBuf(cur)
  const domain = readSecBuf(cur)
  const user = readSecBuf(cur)
  const workstation = readSecBuf(cur)
  const sessionKey = readSecBuf(cur)
  const flags = cur.u32(true) ?? 0
  for (const b of [lmResponse, ntResponse, domain, user, workstation, sessionKey]) {
    if (b && !bufInRange(b, byteLength)) issues.push('ntlm-buffer-oob')
  }
  return {
    messageType: 3,
    lmResponse: lmResponse ?? undefined,
    ntResponse: ntResponse ?? undefined,
    domain: domain ?? undefined,
    user: user ?? undefined,
    workstation: workstation ?? undefined,
    sessionKey: sessionKey ?? undefined,
    negotiateFlags: flags,
    issues,
  }
}

function maskBuf(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  messageAbs: number,
  buf: NtlmSecurityBuffer | undefined,
  reason: string,
): void {
  if (!buf || buf.length <= 0) return
  const abs = messageAbs + buf.offset
  const fill = createProtocolNeutralMaskFill({
    length: buf.length,
    packetIndex,
    offset: abs,
    domain: reason,
  })
  collector.maskRange(abs, fill)
  intents?.recordMaskRange(packetIndex, abs, buf.length, reason, 'ntlmssp')
}

function mapUtf16Identity(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  messageAbs: number,
  messageWindow: Uint8Array,
  buf: NtlmSecurityBuffer | undefined,
  category: 'hostname' | 'user-id',
): void {
  if (!buf || buf.length < 2 || buf.length % 2 !== 0) return
  if (buf.offset + buf.length > messageWindow.length) {
    maskBuf(collector, intents, packetIndex, messageAbs, buf, 'ntlm-buffer-oob')
    return
  }
  const abs = messageAbs + buf.offset
  const slice = messageWindow.subarray(buf.offset, buf.offset + buf.length)
  const text = decodeUtf16(slice, 'le')
  if (!text || text.length === 0) {
    maskBuf(collector, intents, packetIndex, messageAbs, buf, 'ntlm-utf16-opaque')
    return
  }
  const canon = canonicalizeIdentity(category, text)
  if (!canon) {
    maskBuf(collector, intents, packetIndex, messageAbs, buf, 'ntlm-identity-opaque')
    return
  }
  // Wire constraint is UTF-16 byte length; alias truncated/padded to code-unit count.
  const codeUnits = buf.length / 2
  const constraint = { kind: 'text-ascii' as const, byteLength: codeUnits }
  intents?.recordEntityReplacement(
    packetIndex,
    abs,
    category,
    canon,
    buf.length,
    constraint,
    text,
  )
  collector.addDeferred(abs, buf.length, ({ mapping: live }) => {
    try {
      const alias = live.aliasFor(category, canon, constraint, text)
      return computeFixedLengthUtf16Bytes(buf.length, alias.slice(0, codeUnits), 'le')
    } catch {
      return createProtocolNeutralMaskFill({
        length: buf.length,
        packetIndex,
        offset: abs,
        domain: 'ntlm-map-fallback',
      })
    }
  }, { fallbackKind: 'binary-mask', protocol: 'ntlmssp', category, packetIndex })
}

/**
 * Sanitize one NTLMSSP message in place: map domain/user/workstation/targetName;
 * always mask LM/NT responses, session key, and target info AV blob (may hold names —
 * AV pairs get a full mask for fail-closed crypto+directory mix).
 */
export function sanitizeNtlmssp(
  buffer: Uint8Array,
  absoluteOffset: number,
  byteLength: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): boolean {
  void mapping
  const parsed = parseNtlmssp(buffer, absoluteOffset, byteLength)
  if (!parsed || parsed.issues.includes('ntlm-buffer-oob')) {
    if (parsed?.issues.includes('ntlm-buffer-oob')) {
      const fill = createProtocolNeutralMaskFill({
        length: byteLength,
        packetIndex,
        offset: absoluteOffset,
        domain: 'ntlm-malformed',
      })
      collector.maskRange(absoluteOffset, fill)
      intents?.recordMaskRange(packetIndex, absoluteOffset, byteLength, 'ntlm-malformed', 'ntlmssp')
    }
    return parsed != null
  }

  const window = buffer.subarray(absoluteOffset, absoluteOffset + byteLength)

  if (parsed.messageType === 1) {
    mapUtf16Identity(collector, intents, packetIndex, absoluteOffset, window, parsed.domain, 'hostname')
    mapUtf16Identity(collector, intents, packetIndex, absoluteOffset, window, parsed.workstation, 'hostname')
  } else if (parsed.messageType === 2) {
    mapUtf16Identity(collector, intents, packetIndex, absoluteOffset, window, parsed.targetName, 'hostname')
    maskBuf(collector, intents, packetIndex, absoluteOffset, parsed.targetInfo, 'ntlm-target-info')
    // Server challenge is at fixed offset 24 for 32 bytes of challenge+reserved — mask challenge.
    if (byteLength >= 32) {
      const fill = createProtocolNeutralMaskFill({
        length: 8,
        packetIndex,
        offset: absoluteOffset + 24,
        domain: 'ntlm-server-challenge',
      })
      collector.maskRange(absoluteOffset + 24, fill)
      intents?.recordMaskRange(packetIndex, absoluteOffset + 24, 8, 'ntlm-server-challenge', 'ntlmssp')
    }
  } else {
    mapUtf16Identity(collector, intents, packetIndex, absoluteOffset, window, parsed.domain, 'hostname')
    mapUtf16Identity(collector, intents, packetIndex, absoluteOffset, window, parsed.user, 'user-id')
    mapUtf16Identity(collector, intents, packetIndex, absoluteOffset, window, parsed.workstation, 'hostname')
    maskBuf(collector, intents, packetIndex, absoluteOffset, parsed.lmResponse, 'ntlm-lm-response')
    maskBuf(collector, intents, packetIndex, absoluteOffset, parsed.ntResponse, 'ntlm-nt-response')
    maskBuf(collector, intents, packetIndex, absoluteOffset, parsed.sessionKey, 'ntlm-session-key')
  }
  return true
}
