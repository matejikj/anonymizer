/**
 * T59 — NAS EPS (TS 24.301) / 5GS (TS 24.501) framing and security-header classification.
 * Cipher presence ≠ confidentiality; EEA0/NEA0 are null ciphers (plaintext path).
 */

export type NasFamily = 'eps-emm' | 'eps-esm' | '5gmm' | '5gsm'

/** Security header outcome for sanitizer branching. */
export type NasSecurityClass =
  | 'plain'
  | 'integrity-only'
  | 'ciphered-null'
  | 'ciphered'
  | 'unknown'

export interface NasFrame {
  readonly family: NasFamily
  readonly security: NasSecurityClass
  readonly securityHeaderType: number
  /** Absolute offset of inner NAS message (after MAC/SQN when protected). */
  readonly messageOffset: number
  readonly messageLength: number
  readonly messageType: number | null
  readonly headerSpan: { offset: number; length: number }
  readonly issues: readonly string[]
}

const PD_EMM = 0x7
const PD_ESM = 0x2
const EPD_5GMM = 0x7e
const EPD_5GSM = 0x2e

/** EPS EMM security header types (TS 24.301). */
const EPS_SEC = {
  PLAIN: 0,
  INTEGRITY: 1,
  INTEGRITY_CIPHERED: 2,
  INTEGRITY_NEW: 3,
  INTEGRITY_CIPHERED_NEW: 4,
  SERVICE_REQUEST: 12, // part of reserved / special
} as const

export function looksLikeNasEps(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 2) return false
  const b0 = buffer[offset]!
  const pd = b0 & 0x0f
  if (pd === PD_ESM) {
    // ESM: bearer|PD + PTI + known message type
    if (length < 3) return false
    return buffer[offset + 2]! in EPS_ESM_MSG
  }
  if (pd !== PD_EMM) return false
  const sec = (b0 >> 4) & 0x0f
  if (sec === 0) {
    // Plain EMM: require known message type (avoid stealing random 0x07 bytes)
    return buffer[offset + 1]! in EPS_EMM_MSG
  }
  // Protected EMM: need MAC+SQN+inner plain header with known type
  if (length < 8) return false
  if (sec < 1 || sec > 4) return false
  const inner = buffer[offset + 6]!
  if ((inner & 0x0f) !== PD_EMM) return false
  if (((inner >> 4) & 0x0f) !== 0) return false
  return buffer[offset + 7]! in EPS_EMM_MSG
}

export function looksLikeNas5gs(buffer: Uint8Array, offset: number, length: number): boolean {
  if (length < 3) return false
  const epd = buffer[offset]!
  if (epd === EPD_5GSM) {
    return buffer[offset + 2]! in G5SM_MSG
  }
  if (epd !== EPD_5GMM) return false
  const sec = buffer[offset + 1]! & 0x0f
  if (sec === 0) return buffer[offset + 2]! in G5MM_MSG
  if (length < 10) return false
  if (sec < 1 || sec > 4) return false
  // Inner starts with EPD again
  if (buffer[offset + 7]! !== EPD_5GMM) return false
  if ((buffer[offset + 8]! & 0x0f) !== 0) return false
  return buffer[offset + 9]! in G5MM_MSG
}

export function looksLikeNas(buffer: Uint8Array, offset: number, length: number): boolean {
  return looksLikeNasEps(buffer, offset, length) || looksLikeNas5gs(buffer, offset, length)
}

/**
 * Classify and locate the inner message. Does not decrypt.
 * `nullCipher` — when carrier/session proves EEA0/NEA0; otherwise ciphered → opaque.
 */
export function parseNasFrame(
  buffer: Uint8Array,
  offset: number,
  length: number,
  opts?: { readonly nullCipher?: boolean },
): NasFrame | null {
  if (length < 2) return null
  if (looksLikeNas5gs(buffer, offset, length)) {
    return parse5gs(buffer, offset, length, opts?.nullCipher === true)
  }
  if (looksLikeNasEps(buffer, offset, length)) {
    return parseEps(buffer, offset, length, opts?.nullCipher === true)
  }
  return null
}

function parseEps(
  buffer: Uint8Array,
  offset: number,
  length: number,
  nullCipher: boolean,
): NasFrame | null {
  const b0 = buffer[offset]!
  const pd = b0 & 0x0f
  const issues: string[] = []

  if (pd === PD_ESM) {
    // ESM: bearer id | PD ; PTI ; message type — always "plain" at this layer
    if (length < 3) return null
    return {
      family: 'eps-esm',
      security: 'plain',
      securityHeaderType: 0,
      messageOffset: offset,
      messageLength: length,
      messageType: buffer[offset + 2]!,
      headerSpan: { offset, length: 3 },
      issues,
    }
  }

  const sec = (b0 >> 4) & 0x0f
  if (sec === EPS_SEC.PLAIN) {
    return {
      family: 'eps-emm',
      security: 'plain',
      securityHeaderType: sec,
      messageOffset: offset,
      messageLength: length,
      messageType: buffer[offset + 1]!,
      headerSpan: { offset, length: 2 },
      issues,
    }
  }

  // Protected: MAC (4) + SQN (1) + NAS message
  if (length < 7) {
    issues.push('nas-eps-protected-short')
    return {
      family: 'eps-emm',
      security: 'unknown',
      securityHeaderType: sec,
      messageOffset: offset,
      messageLength: length,
      messageType: null,
      headerSpan: { offset, length: 1 },
      issues,
    }
  }

  const security = classifyProtected(sec, nullCipher)
  const innerOff = offset + 6
  const innerLen = length - 6
  const msgType = innerLen >= 2 ? buffer[innerOff + 1]! : null

  return {
    family: 'eps-emm',
    security,
    securityHeaderType: sec,
    messageOffset: security === 'ciphered' ? innerOff : innerOff,
    messageLength: innerLen,
    messageType: security === 'ciphered' ? null : msgType,
    headerSpan: { offset, length: 6 },
    issues,
  }
}

function parse5gs(
  buffer: Uint8Array,
  offset: number,
  length: number,
  nullCipher: boolean,
): NasFrame | null {
  const epd = buffer[offset]!
  const issues: string[] = []

  if (epd === EPD_5GSM) {
    if (length < 3) return null
    return {
      family: '5gsm',
      security: 'plain',
      securityHeaderType: 0,
      messageOffset: offset,
      messageLength: length,
      messageType: buffer[offset + 2]!,
      headerSpan: { offset, length: 3 },
      issues,
    }
  }

  // 5GMM: EPD | security header type | …
  const sec = buffer[offset + 1]! & 0x0f
  if (sec === 0) {
    if (length < 3) return null
    return {
      family: '5gmm',
      security: 'plain',
      securityHeaderType: 0,
      messageOffset: offset,
      messageLength: length,
      messageType: buffer[offset + 2]!,
      headerSpan: { offset, length: 3 },
      issues,
    }
  }

  // Protected 5GMM: EPD + sec hdr + MAC(4) + SQN(1) + message
  if (length < 8) {
    issues.push('nas-5gs-protected-short')
    return {
      family: '5gmm',
      security: 'unknown',
      securityHeaderType: sec,
      messageOffset: offset,
      messageLength: length,
      messageType: null,
      headerSpan: { offset, length: 2 },
      issues,
    }
  }

  const security = classifyProtected(sec, nullCipher)
  const innerOff = offset + 7
  const innerLen = length - 7
  const msgType = innerLen >= 3 ? buffer[innerOff + 2]! : null

  return {
    family: '5gmm',
    security,
    securityHeaderType: sec,
    messageOffset: innerOff,
    messageLength: innerLen,
    messageType: security === 'ciphered' ? null : msgType,
    headerSpan: { offset, length: 7 },
    issues,
  }
}

function classifyProtected(sec: number, nullCipher: boolean): NasSecurityClass {
  // 1,3 = integrity only; 2,4 = integrity+ciphered
  if (sec === 1 || sec === 3) return 'integrity-only'
  if (sec === 2 || sec === 4) {
    return nullCipher ? 'ciphered-null' : 'ciphered'
  }
  return 'unknown'
}

/** EPS/5GS message type names used in coverage/diagnostics (not exhaustive). */
export const EPS_EMM_MSG: Readonly<Record<number, string>> = {
  0x41: 'attach-request',
  0x42: 'attach-accept',
  0x43: 'attach-complete',
  0x44: 'attach-reject',
  0x45: 'detach-request',
  0x46: 'detach-accept',
  0x52: 'auth-request',
  0x53: 'auth-response',
  0x54: 'auth-reject',
  0x55: 'identity-request',
  0x56: 'identity-response',
  0x5d: 'security-mode-command',
  0x5e: 'security-mode-complete',
  0x5f: 'security-mode-reject',
}

export const EPS_ESM_MSG: Readonly<Record<number, string>> = {
  0xc1: 'activate-default-eps-bearer-request',
  0xc2: 'activate-default-eps-bearer-accept',
  0xd0: 'pdn-connectivity-request',
  0xd1: 'pdn-connectivity-reject',
}

export const G5MM_MSG: Readonly<Record<number, string>> = {
  0x41: 'registration-request',
  0x42: 'registration-accept',
  0x43: 'registration-complete',
  0x44: 'registration-reject',
  0x45: 'deregistration-request-ue',
  0x56: 'auth-request',
  0x57: 'auth-response',
  0x5c: 'identity-request',
  0x5d: 'identity-response',
  0x5e: 'security-mode-command',
  0x5f: 'security-mode-complete',
}

export const G5SM_MSG: Readonly<Record<number, string>> = {
  0xc1: 'pdu-session-establishment-request',
  0xc2: 'pdu-session-establishment-accept',
  0xc3: 'pdu-session-establishment-reject',
}
