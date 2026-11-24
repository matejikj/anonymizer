/**
 * TLS record sanitizer (CF-10 / enterprise step 10).
 *
 * Port-independent: every sniffed TLS record goes through this dispatcher.
 * Handshake plaintext is never marked `encrypted`. Application Data may be
 * retained as ciphertext with `tls-encrypted-payload` / `encrypted`.
 *
 * Explicit branches (step 10):
 * - TLS 1.2: plaintext Certificate → MAP readable CN/SAN; mask remaining DER.
 * - TLS 1.3: after ServerHello, Application Data (EncryptedExtensions+) → ENCRYPTED_OPAQUE.
 * - ECH (RFC 9849): Outer ClientHello parsed normally; outer SNI (public_name) MAP;
 *   ECH encrypted payload PRESERVE / ENCRYPTED_OPAQUE — never treat whole CH as opaque.
 */

import type { PatchCollector } from './PatchCollector'
import type { MappingLike } from '../anonymization/mapping'
import type { AppLayerResult, LayerCoverage } from './types'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { looksLikeTlsRecord } from './mediaPolicy'
import type { IntentCollector } from '../discovery/intentCollector'
import { createProtocolNeutralMaskFill } from './maskFill'
import type { SensitiveField } from '../trust'
import { sanitizeCertificateDerIdentities } from './tlsCertIdentities'
import { tlsBranchIssue, type TlsHandshakeBranch } from './tlsBranches'

const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14
const TLS_CONTENT_TYPE_ALERT = 0x15
const TLS_CONTENT_TYPE_HANDSHAKE = 0x16
const TLS_CONTENT_TYPE_APPLICATION_DATA = 0x17

const TLS_HANDSHAKE_CLIENT_HELLO = 0x01
const TLS_HANDSHAKE_SERVER_HELLO = 0x02
const TLS_HANDSHAKE_NEW_SESSION_TICKET = 0x04
const TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS = 0x08
const TLS_HANDSHAKE_CERTIFICATE = 0x0b
const TLS_HANDSHAKE_CERTIFICATE_REQUEST = 0x0d
const TLS_HANDSHAKE_CERTIFICATE_VERIFY = 0x0f
const TLS_HANDSHAKE_FINISHED = 0x14
const TLS_HANDSHAKE_KEY_UPDATE = 0x18

const TLS_EXTENSION_SERVER_NAME = 0x0000
const TLS_EXTENSION_SUPPORTED_GROUPS = 0x000a
const TLS_EXTENSION_EC_POINT_FORMATS = 0x000b
const TLS_EXTENSION_SIGNATURE_ALGORITHMS = 0x000d
const TLS_EXTENSION_ALPN = 0x0010
const TLS_EXTENSION_SUPPORTED_VERSIONS = 0x002b
const TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES = 0x002d
/** RFC 9849 encrypted_client_hello */
const TLS_EXTENSION_ECH = 0xfe0d
/** Draft legacy ECH type still seen in some captures */
const TLS_EXTENSION_ECH_DRAFT = 0xffce

/**
 * T47 — extension *values* that may stay as negotiation metadata (type+length always kept).
 * Key material (key_share, PSK, cookie, …) and unknown types are masked.
 */
const TLS_EXTENSION_PRESERVE_VALUE = new Set<number>([
  TLS_EXTENSION_SUPPORTED_GROUPS,
  TLS_EXTENSION_EC_POINT_FORMATS,
  TLS_EXTENSION_SIGNATURE_ALGORITHMS,
  TLS_EXTENSION_ALPN,
  TLS_EXTENSION_SUPPORTED_VERSIONS,
  TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES,
])

const SNI_HOST_NAME_TYPE = 0x00
const ECH_CLIENT_HELLO_OUTER = 0x00
const TLS_VERSION_1_3 = 0x0304

interface TlsSanitizeContext {
  branches: Set<TlsHandshakeBranch>
  fields: SensitiveField[]
  issues: string[]
  /** True after a ServerHello that negotiated TLS 1.3 in this TCP payload. */
  sawTls13ServerHello: boolean
}

export function sanitizeTls(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents?: IntentCollector,
  packetIndex = 0,
): AppLayerResult | null {
  if (!looksLikeTlsRecord(buffer, offset, length)) {
    return null
  }

  const coverage: LayerCoverage[] = []
  const ctx: TlsSanitizeContext = {
    branches: new Set(),
    fields: [],
    issues: [],
    sawTls13ServerHello: false,
  }
  let cursor = offset
  const end = offset + length

  while (cursor + 5 <= end) {
    const contentType = buffer[cursor]!
    if (!isTlsContentType(contentType) || buffer[cursor + 1] !== 0x03) {
      break
    }

    const recordLength = (buffer[cursor + 3]! << 8) | buffer[cursor + 4]!
    const recordBodyStart = cursor + 5
    const recordEnd = recordBodyStart + recordLength
    const totalRecordLen = 5 + recordLength

    if (recordEnd > end) {
      coverage.push({
        protocol: 'tls',
        offset: cursor,
        length: end - cursor,
        status: 'requires-reassembly',
      })
      break
    }

    switch (contentType) {
      case TLS_CONTENT_TYPE_APPLICATION_DATA:
        if (ctx.sawTls13ServerHello) {
          noteBranch(ctx, 'tls-1.3')
          ctx.fields.push({
            type: 'tls-encrypted-extensions',
            start: recordBodyStart,
            length: recordLength,
            classification: 'ENCRYPTED_OPAQUE',
          })
          coverage.push({
            protocol: 'tls-1.3',
            offset: cursor,
            length: totalRecordLen,
            status: 'encrypted',
          })
        } else {
          coverage.push({
            protocol: 'tls-encrypted-payload',
            offset: cursor,
            length: totalRecordLen,
            status: 'encrypted',
          })
        }
        break
      case TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
        coverage.push({
          protocol: 'tls-encrypted-payload',
          offset: cursor,
          length: totalRecordLen,
          status: 'encrypted',
        })
        break
      case TLS_CONTENT_TYPE_ALERT:
        coverage.push({
          protocol: 'tls-handshake-unsupported',
          offset: cursor,
          length: totalRecordLen,
          status: 'unsupported',
        })
        break
      case TLS_CONTENT_TYPE_HANDSHAKE:
        coverage.push(...sanitizeHandshakeRecord(
          buffer,
          cursor,
          totalRecordLen,
          recordBodyStart,
          recordEnd,
          collector,
          mapping,
          intents,
          packetIndex,
          ctx,
        ))
        break
      default:
        coverage.push({
          protocol: 'tls',
          offset: cursor,
          length: totalRecordLen,
          status: 'unsupported',
        })
        break
    }

    cursor = recordEnd
  }

  if (coverage.length === 0) return null

  for (const branch of ctx.branches) {
    ctx.issues.push(tlsBranchIssue(branch))
  }

  return {
    coverage,
    fields: ctx.fields.length > 0 ? ctx.fields : undefined,
    issues: ctx.issues.length > 0 ? ctx.issues : undefined,
  }
}

function noteBranch(ctx: TlsSanitizeContext, branch: TlsHandshakeBranch): void {
  ctx.branches.add(branch)
}

function isTlsContentType(value: number): boolean {
  return value === TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC
    || value === TLS_CONTENT_TYPE_ALERT
    || value === TLS_CONTENT_TYPE_HANDSHAKE
    || value === TLS_CONTENT_TYPE_APPLICATION_DATA
}

/**
 * A TLS record's fragment payload can carry more than one handshake message
 * back-to-back (e.g. ServerHello + Certificate + ServerHelloDone coalesced into a
 * single record). Iterate every 4-byte handshake header from `bodyStart` to
 * `recordEnd` and sanitize each message individually — a coverage span must never
 * claim bytes belonging to a message it did not actually decode.
 */
/** Coalesced TLS/DTLS handshake bytes (after record header) — shared by dtls.ts and tls.ts. */
export function sanitizeCoalescedTlsHandshakes(
  buffer: Uint8Array,
  recordOffset: number,
  bodyStart: number,
  recordEnd: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix = 'tls',
): { coverage: LayerCoverage[]; issues: string[] } {
  const ctx: TlsSanitizeContext = {
    branches: new Set(),
    fields: [],
    issues: [],
    sawTls13ServerHello: false,
  }
  const raw = sanitizeHandshakeRecord(
    buffer,
    recordOffset,
    recordEnd - recordOffset,
    bodyStart,
    recordEnd,
    collector,
    mapping,
    intents,
    packetIndex,
    ctx,
  )
  const coverage =
    protocolPrefix === 'tls'
      ? raw
      : raw.map((c) => ({
          ...c,
          protocol: c.protocol.startsWith('tls') ? `${protocolPrefix}${c.protocol.slice(3)}` : c.protocol,
        }))
  return { coverage, issues: ctx.issues }
}

/** One complete TLS handshake message body (4-byte TLS header already stripped). */
export function sanitizeOneTlsHandshakeMessage(
  buffer: Uint8Array,
  coverageOffset: number,
  coverageLength: number,
  handshakeType: number,
  bodyStart: number,
  bodyEnd: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  protocolPrefix = 'tls',
): { coverage: LayerCoverage[]; issues: string[] } {
  const ctx: TlsSanitizeContext = {
    branches: new Set(),
    fields: [],
    issues: [],
    sawTls13ServerHello: false,
  }
  const raw = sanitizeHandshakeMessage(
    buffer,
    coverageOffset,
    coverageLength,
    coverageOffset,
    coverageLength,
    handshakeType,
    bodyStart,
    bodyEnd,
    collector,
    mapping,
    intents,
    packetIndex,
    ctx,
  )
  const coverage =
    protocolPrefix === 'tls'
      ? raw
      : raw.map((c) => ({
          ...c,
          protocol: c.protocol.startsWith('tls') ? `${protocolPrefix}${c.protocol.slice(3)}` : c.protocol,
        }))
  return { coverage, issues: ctx.issues }
}

function sanitizeHandshakeRecord(
  buffer: Uint8Array,
  recordOffset: number,
  _totalRecordLen: number,
  bodyStart: number,
  recordEnd: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  ctx: TlsSanitizeContext,
): LayerCoverage[] {
  const coverage: LayerCoverage[] = []
  let pos = bodyStart
  let messageCount = 0

  while (pos < recordEnd) {
    const spanStart = messageCount === 0 ? recordOffset : pos

    if (recordEnd - pos < 4) {
      coverage.push({
        protocol: 'tls',
        offset: spanStart,
        length: recordEnd - spanStart,
        status: messageCount === 0 ? 'malformed' : 'requires-reassembly',
      })
      return coverage
    }

    const handshakeType = buffer[pos]!
    const handshakeBodyLength =
      (buffer[pos + 1]! << 16) | (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const messageOffset = pos
    const messageBodyStart = pos + 4
    const handshakeEnd = messageBodyStart + handshakeBodyLength

    if (handshakeEnd > recordEnd) {
      coverage.push({
        protocol: 'tls',
        offset: spanStart,
        length: recordEnd - spanStart,
        status: messageCount === 0 ? 'malformed' : 'requires-reassembly',
      })
      return coverage
    }

    coverage.push(...sanitizeHandshakeMessage(
      buffer,
      messageOffset,
      handshakeEnd - messageOffset,
      spanStart,
      handshakeEnd - spanStart,
      handshakeType,
      messageBodyStart,
      handshakeEnd,
      collector,
      mapping,
      intents,
      packetIndex,
      ctx,
    ))
    pos = handshakeEnd
    messageCount++
  }

  return coverage
}

/** Sanitize exactly one handshake message; coverage spans cover only this message. */
function sanitizeHandshakeMessage(
  buffer: Uint8Array,
  _messageOffset: number,
  _messageLength: number,
  coverageOffset: number,
  coverageLength: number,
  handshakeType: number,
  pos: number,
  handshakeEnd: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  ctx: TlsSanitizeContext,
): LayerCoverage[] {
  const malformed = (): LayerCoverage[] => ([{
    protocol: 'tls',
    offset: coverageOffset,
    length: coverageLength,
    status: 'malformed',
  }])
  const handshakeBodyLength = handshakeEnd - pos

  switch (handshakeType) {
    case TLS_HANDSHAKE_CLIENT_HELLO: {
      const ok = sanitizeClientHelloBody(
        buffer, pos, handshakeEnd, collector, mapping, intents, packetIndex, ctx,
      )
      if (!ok) return malformed()
      return [{
        protocol: 'tls-clienthello',
        offset: coverageOffset,
        length: coverageLength,
        status: 'covered',
      }]
    }
    case TLS_HANDSHAKE_SERVER_HELLO: {
      const ok = sanitizeServerHelloBody(buffer, pos, handshakeEnd, collector, intents, packetIndex, ctx)
      if (!ok) return malformed()
      return [{
        protocol: 'tls-serverhello',
        offset: coverageOffset,
        length: coverageLength,
        status: 'covered',
      }]
    }
    case TLS_HANDSHAKE_CERTIFICATE: {
      // TLS 1.3 Certificate in plaintext after SH would be unusual; still sanitize.
      // Plaintext Certificate is the TLS 1.2 branch.
      if (!ctx.sawTls13ServerHello) {
        noteBranch(ctx, 'tls-1.2')
      }
      const ok = sanitizeCertificateBody(buffer, pos, handshakeEnd, collector, mapping, intents, packetIndex)
      if (!ok && handshakeBodyLength > 0) {
        maskOpaque(buffer, pos, handshakeBodyLength, collector, intents, packetIndex, 'tls-certificate-opaque')
      }
      return [{
        protocol: 'tls-certificate',
        offset: coverageOffset,
        length: coverageLength,
        status: 'covered',
      }]
    }
    case TLS_HANDSHAKE_CERTIFICATE_VERIFY: {
      if (handshakeBodyLength > 0) {
        maskOpaque(buffer, pos, handshakeBodyLength, collector, intents, packetIndex, 'tls-cert-verify')
      }
      return [{
        protocol: 'tls-certificate',
        offset: coverageOffset,
        length: coverageLength,
        status: 'covered',
      }]
    }
    case TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS:
    case TLS_HANDSHAKE_NEW_SESSION_TICKET:
    case TLS_HANDSHAKE_CERTIFICATE_REQUEST:
    case TLS_HANDSHAKE_KEY_UPDATE: {
      // TLS 1.3 post-SH messages should be inside Application Data. If seen as
      // plaintext handshake, still treat as ENCRYPTED_OPAQUE / fail-closed mask.
      noteBranch(ctx, 'tls-1.3')
      if (handshakeBodyLength > 0) {
        maskOpaque(
          buffer, pos, handshakeBodyLength, collector, intents, packetIndex,
          `tls-handshake-${handshakeType}`,
        )
      }
      ctx.fields.push({
        type: 'tls-encrypted-extensions',
        start: pos,
        length: Math.max(0, handshakeBodyLength),
        classification: 'ENCRYPTED_OPAQUE',
      })
      return [{
        protocol: 'tls-1.3',
        offset: coverageOffset,
        length: coverageLength,
        status: 'encrypted',
      }]
    }
    case TLS_HANDSHAKE_FINISHED:
      return [{
        protocol: 'tls-encrypted-payload',
        offset: coverageOffset,
        length: coverageLength,
        status: 'encrypted',
      }]
    default:
      if (handshakeBodyLength > 0) {
        maskOpaque(
          buffer,
          pos,
          handshakeBodyLength,
          collector,
          intents,
          packetIndex,
          `tls-handshake-${handshakeType}`,
        )
      }
      return [{
        protocol: 'tls-handshake-unsupported',
        offset: coverageOffset,
        length: coverageLength,
        status: 'redacted',
      }]
  }
}

function maskOpaque(
  _buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  const fill = createProtocolNeutralMaskFill({ length, packetIndex, offset, domain })
  collector.maskRange(offset, fill)
  intents?.recordMaskRange(packetIndex, offset, length, domain, 'tls')
}

/** Returns false when the ClientHello structure is malformed. */
function sanitizeClientHelloBody(
  buffer: Uint8Array,
  start: number,
  handshakeEnd: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  ctx: TlsSanitizeContext,
): boolean {
  let pos = start

  // client_version(2) — structure / negotiation fact (preserve)
  if (pos + 2 > handshakeEnd) return false
  pos += 2

  // T47 — client_random(32): may carry GMT unix time (TLS 1.2) and is a session correlator.
  if (pos + 32 > handshakeEnd) return false
  maskOpaque(buffer, pos, 32, collector, intents, packetIndex, 'tls-client-random')
  pos += 32

  // session_id: redact opaque bytes (identity/session correlator)
  if (pos + 1 > handshakeEnd) return false
  const sessionIdLen = buffer[pos]!
  pos += 1
  if (pos + sessionIdLen > handshakeEnd) return false
  if (sessionIdLen > 0) {
    maskOpaque(buffer, pos, sessionIdLen, collector, intents, packetIndex, 'tls-session-id')
  }
  pos += sessionIdLen

  // cipher_suites — negotiation list (preserve)
  if (pos + 2 > handshakeEnd) return false
  const cipherSuitesLen = (buffer[pos]! << 8) | buffer[pos + 1]!
  pos += 2
  if (pos + cipherSuitesLen > handshakeEnd) return false
  pos += cipherSuitesLen

  // compression_methods (preserve)
  if (pos + 1 > handshakeEnd) return false
  const compressionLen = buffer[pos]!
  pos += 1
  if (pos + compressionLen > handshakeEnd) return false
  pos += compressionLen

  // extensions (optional)
  if (pos + 2 > handshakeEnd) return true
  const extensionsLen = (buffer[pos]! << 8) | buffer[pos + 1]!
  pos += 2
  const extensionsEnd = pos + extensionsLen
  if (extensionsEnd > handshakeEnd) return false

  while (pos + 4 <= extensionsEnd) {
    const extType = (buffer[pos]! << 8) | buffer[pos + 1]!
    const extLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const extDataStart = pos + 4
    const extDataEnd = extDataStart + extLen
    if (extDataEnd > extensionsEnd) return false

    if (extType === TLS_EXTENSION_SERVER_NAME) {
      sanitizeServerNameExtension(
        buffer, extDataStart, extDataEnd, collector, mapping, intents, packetIndex,
      )
    } else if (extType === TLS_EXTENSION_SUPPORTED_VERSIONS) {
      if (extensionOffersTls13(buffer, extDataStart, extDataEnd)) {
        // Client offers 1.3 — definitive branch waits for ServerHello; note offer only via fields.
        ctx.fields.push({
          type: 'tls-supported-versions',
          start: extDataStart,
          length: extLen,
          classification: 'SAFE_METADATA',
        })
      }
    } else if (extType === TLS_EXTENSION_ECH || extType === TLS_EXTENSION_ECH_DRAFT) {
      sanitizeEncryptedClientHelloExtension(
        buffer, extDataStart, extDataEnd, ctx,
      )
    } else if (
      extLen > 0 &&
      !TLS_EXTENSION_PRESERVE_VALUE.has(extType)
    ) {
      // T47 — unknown / key-material extension values (key_share, PSK, cookie, …).
      maskOpaque(
        buffer, extDataStart, extLen, collector, intents, packetIndex,
        `tls-extension-${extType}`,
      )
    }

    pos = extDataEnd
  }

  return true
}

function sanitizeServerHelloBody(
  buffer: Uint8Array,
  start: number,
  handshakeEnd: number,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  ctx: TlsSanitizeContext,
): boolean {
  let pos = start

  // server_version(2) — structure / negotiation fact (preserve)
  if (pos + 2 > handshakeEnd) return false
  pos += 2

  // T47 — server_random(32): not public structure; legacy GMT prefix + correlator.
  if (pos + 32 > handshakeEnd) return false
  maskOpaque(buffer, pos, 32, collector, intents, packetIndex, 'tls-server-random')
  pos += 32

  if (pos + 1 > handshakeEnd) return false
  const sessionIdLen = buffer[pos]!
  pos += 1
  if (pos + sessionIdLen > handshakeEnd) return false
  if (sessionIdLen > 0) {
    maskOpaque(buffer, pos, sessionIdLen, collector, intents, packetIndex, 'tls-session-id')
  }
  pos += sessionIdLen

  // cipher_suite(2) + compression(1) — negotiation facts (preserve)
  if (pos + 3 > handshakeEnd) return false
  pos += 3

  // extensions optional
  if (pos + 2 > handshakeEnd) return true
  const extensionsLen = (buffer[pos]! << 8) | buffer[pos + 1]!
  pos += 2
  const extensionsEnd = pos + extensionsLen
  if (extensionsEnd > handshakeEnd) return false

  while (pos + 4 <= extensionsEnd) {
    const extType = (buffer[pos]! << 8) | buffer[pos + 1]!
    const extLen = (buffer[pos + 2]! << 8) | buffer[pos + 3]!
    const extDataStart = pos + 4
    const extDataEnd = extDataStart + extLen
    if (extDataEnd > extensionsEnd) return false

    if (extType === TLS_EXTENSION_SUPPORTED_VERSIONS) {
      if (serverHelloSelectedTls13(buffer, extDataStart, extDataEnd)) {
        ctx.sawTls13ServerHello = true
        noteBranch(ctx, 'tls-1.3')
      }
      // preserve value — selected version is negotiation metadata
    } else if (
      extLen > 0 &&
      !TLS_EXTENSION_PRESERVE_VALUE.has(extType)
    ) {
      maskOpaque(
        buffer, extDataStart, extLen, collector, intents, packetIndex,
        `tls-extension-${extType}`,
      )
    }

    pos = extDataEnd
  }

  return true
}

function sanitizeCertificateBody(
  buffer: Uint8Array,
  start: number,
  handshakeEnd: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): boolean {
  let pos = start
  if (pos + 3 > handshakeEnd) return false
  const certsLen =
    (buffer[pos]! << 16) | (buffer[pos + 1]! << 8) | buffer[pos + 2]!
  pos += 3
  const certsEnd = pos + certsLen
  if (certsEnd > handshakeEnd) return false

  while (pos + 3 <= certsEnd) {
    const certLen =
      (buffer[pos]! << 16) | (buffer[pos + 1]! << 8) | buffer[pos + 2]!
    pos += 3
    if (pos + certLen > certsEnd) return false
    if (certLen > 0) {
      sanitizeCertificateDerIdentities(
        buffer, pos, certLen, collector, mapping, intents, packetIndex,
      )
    }
    pos += certLen
  }
  return true
}

/**
 * RFC 9849 ClientHello Outer encrypted_client_hello:
 * type(1)=outer | cipher_suite(4) | config_id(1) | enc<0..2^16-1> | payload<1..2^16-1>
 * Encrypted payload → ENCRYPTED_OPAQUE / PRESERVE (do not mask ciphertext).
 */
function sanitizeEncryptedClientHelloExtension(
  buffer: Uint8Array,
  start: number,
  end: number,
  ctx: TlsSanitizeContext,
): void {
  noteBranch(ctx, 'ech')
  if (start >= end) return

  const type = buffer[start]!
  if (type !== ECH_CLIENT_HELLO_OUTER) {
    // Inner must not appear on the wire in Outer CH; treat whole extension as opaque encrypted.
    ctx.fields.push({
      type: 'tls-ech-inner',
      start,
      length: end - start,
      classification: 'ENCRYPTED_OPAQUE',
    })
    return
  }

  let pos = start + 1
  // cipher_suite (HpkeSymmetricCipherSuite = kdf_id + aead_id) = 4 bytes
  if (pos + 4 > end) return
  pos += 4
  // config_id
  if (pos + 1 > end) return
  pos += 1
  // enc
  if (pos + 2 > end) return
  const encLen = (buffer[pos]! << 8) | buffer[pos + 1]!
  pos += 2
  if (pos + encLen > end) return
  pos += encLen
  // payload — encrypted ClientHelloInner
  if (pos + 2 > end) return
  const payloadLen = (buffer[pos]! << 8) | buffer[pos + 1]!
  pos += 2
  if (pos + payloadLen > end) return

  ctx.fields.push({
    type: 'tls-ech-payload',
    start: pos,
    length: payloadLen,
    classification: 'ENCRYPTED_OPAQUE',
  })
  // PRESERVE ciphertext bytes — no maskRange.
}

function extensionOffersTls13(buffer: Uint8Array, start: number, end: number): boolean {
  // ClientHello: opaque versions<2..254> = length(1) + version list
  if (start >= end) return false
  const listLen = buffer[start]!
  let pos = start + 1
  const listEnd = Math.min(pos + listLen, end)
  while (pos + 2 <= listEnd) {
    const ver = (buffer[pos]! << 8) | buffer[pos + 1]!
    if (ver === TLS_VERSION_1_3) return true
    pos += 2
  }
  return false
}

function serverHelloSelectedTls13(buffer: Uint8Array, start: number, end: number): boolean {
  // ServerHello supported_versions: selected version (2 bytes)
  if (start + 2 > end) return false
  const ver = (buffer[start]! << 8) | buffer[start + 1]!
  return ver === TLS_VERSION_1_3
}

function sanitizeServerNameExtension(
  buffer: Uint8Array,
  start: number,
  end: number,
  collector: PatchCollector,
  _mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  let sp = start
  if (sp + 2 > end) return
  const listLen = (buffer[sp]! << 8) | buffer[sp + 1]!
  sp += 2
  const listEnd = Math.min(sp + listLen, end)

  while (sp + 3 <= listEnd) {
    const nameType = buffer[sp]!
    const nameLen = (buffer[sp + 1]! << 8) | buffer[sp + 2]!
    const nameStart = sp + 3
    const nameEnd = nameStart + nameLen
    if (nameEnd > listEnd) return

    if (nameType === SNI_HOST_NAME_TYPE && nameLen > 0) {
      let sni = ''
      for (let i = 0; i < nameLen; i++) sni += String.fromCharCode(buffer[nameStart + i]!)
      intents?.recordEntityReplacement(
        packetIndex,
        nameStart,
        'hostname',
        sni,
        nameLen,
        { kind: 'text-ascii', byteLength: nameLen },
        sni,
      )
      collector.addDeferred(nameStart, nameLen, ({ mapping: liveMapping }) => {
        const mapped = liveMapping.aliasFor(
          'hostname',
          sni,
          { kind: 'text-ascii', byteLength: nameLen },
          sni,
        )
        return computeFixedLengthAsciiBytes(nameStart, nameLen, mapped)
      })
    }

    sp = nameEnd
  }
}
