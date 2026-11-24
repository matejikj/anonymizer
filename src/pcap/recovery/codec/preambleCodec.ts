/**
 * Recovery preamble codec — v4 publicHeader (no KDF/AEAD/wrap material).
 */

import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import { RecoveryReader, RecoveryWriter } from './binaryIO'
import {
  RECOVERY_ENCRYPTED_FORMAT_VERSION,
  RECOVERY_ENCRYPTED_UNSUPPORTED_MESSAGE,
  RECOVERY_FORMAT_VERSION,
  RECOVERY_MAGIC_BYTES,
  RECOVERY_MANDATORY_FLAGS_NONE,
  RECOVERY_OPTIONAL_FLAGS_NONE,
  RECOVERY_PREAMBLE_LENGTH,
  RECOVERY_SCHEMA_VERSION,
} from './formatConstants'

export interface RecoveryPreamble {
  readonly formatVersion: number
  readonly schemaVersion: number
  readonly headerLength: number
  readonly mandatoryFlags: number
  readonly optionalFlags: number
  readonly recoveryId: Uint8Array
  readonly anonymizedSha256Prefix64: Uint8Array
  readonly bytes: Uint8Array
}

export function writePreamble(input: {
  recoveryId: Uint8Array
  anonymizedSha256Prefix64: Uint8Array
  mandatoryFlags?: number
  optionalFlags?: number
}): PcapRecoveryResult<Uint8Array> {
  if (input.recoveryId.byteLength !== PCAP_RECOVERY_LIMITS.recoveryIdBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'invalid recoveryId length')
  }
  if (input.anonymizedSha256Prefix64.byteLength !== PCAP_RECOVERY_LIMITS.anonymizedHashPrefixBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'invalid hash prefix length')
  }

  const headerLength = RECOVERY_PREAMBLE_LENGTH
  if (headerLength > PCAP_RECOVERY_LIMITS.maxPreambleBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'preamble exceeds limit')
  }
  const w = new RecoveryWriter()
  w.writeBytes(RECOVERY_MAGIC_BYTES)
  w.writeU16(RECOVERY_FORMAT_VERSION)
  w.writeU16(RECOVERY_SCHEMA_VERSION)
  w.writeU16(headerLength)
  w.writeU16(input.mandatoryFlags ?? RECOVERY_MANDATORY_FLAGS_NONE)
  w.writeU16(input.optionalFlags ?? RECOVERY_OPTIONAL_FLAGS_NONE)
  w.writeU16(0)
  w.writeBytes(input.recoveryId)
  w.writeBytes(input.anonymizedSha256Prefix64)
  const bytes = w.toUint8Array()
  if (bytes.byteLength !== headerLength) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'preamble length mismatch')
  }
  return recoveryOk(bytes)
}

export function parsePreamble(bytes: Uint8Array): PcapRecoveryResult<RecoveryPreamble> {
  if (bytes.byteLength < 12) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'preamble too short')
  }
  const peek = new RecoveryReader(bytes, 0, Math.min(bytes.byteLength, PCAP_RECOVERY_LIMITS.maxPreambleBytes))
  const magic = peek.readBytes(8, 8)
  if (!magic.ok) return magic
  if (!bytesEqualConst(magic.value, RECOVERY_MAGIC_BYTES)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'invalid magic')
  }
  const formatVersion = peek.readU16()
  if (!formatVersion.ok) return formatVersion
  const schemaVersion = peek.readU16()
  if (!schemaVersion.ok) return schemaVersion

  if (formatVersion.value === RECOVERY_ENCRYPTED_FORMAT_VERSION) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, RECOVERY_ENCRYPTED_UNSUPPORTED_MESSAGE)
  }
  if (formatVersion.value !== RECOVERY_FORMAT_VERSION || schemaVersion.value !== RECOVERY_SCHEMA_VERSION) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'unsupported recovery version')
  }

  const headerLength = peek.readU16()
  if (!headerLength.ok) return headerLength
  if (headerLength.value > PCAP_RECOVERY_LIMITS.maxPreambleBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'preamble exceeds limit')
  }
  if (headerLength.value !== RECOVERY_PREAMBLE_LENGTH) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'preamble length mismatch')
  }
  if (bytes.byteLength < headerLength.value) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'truncated preamble')
  }

  const r = new RecoveryReader(bytes, 0, headerLength.value)
  r.readBytes(8, 8)
  r.readU16()
  r.readU16()
  r.readU16()
  const mandatoryFlags = r.readU16()
  if (!mandatoryFlags.ok) return mandatoryFlags
  if (mandatoryFlags.value !== RECOVERY_MANDATORY_FLAGS_NONE) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'unknown mandatory flag')
  }
  const optionalFlags = r.readU16()
  if (!optionalFlags.ok) return optionalFlags
  const reserved0 = r.readU16()
  if (!reserved0.ok) return reserved0
  if (reserved0.value !== 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'reserved bytes must be zero')
  }
  const recoveryId = r.readBytes(
    PCAP_RECOVERY_LIMITS.recoveryIdBytes,
    PCAP_RECOVERY_LIMITS.recoveryIdBytes,
  )
  if (!recoveryId.ok) return recoveryId
  const hashPrefix = r.readBytes(
    PCAP_RECOVERY_LIMITS.anonymizedHashPrefixBytes,
    PCAP_RECOVERY_LIMITS.anonymizedHashPrefixBytes,
  )
  if (!hashPrefix.ok) return hashPrefix
  const consumed = r.expectConsumed()
  if (!consumed.ok) return consumed

  const canonical = bytes.subarray(0, headerLength.value).slice()
  return recoveryOk({
    formatVersion: formatVersion.value,
    schemaVersion: schemaVersion.value,
    headerLength: headerLength.value,
    mandatoryFlags: mandatoryFlags.value,
    optionalFlags: optionalFlags.value,
    recoveryId: recoveryId.value,
    anonymizedSha256Prefix64: hashPrefix.value,
    bytes: canonical,
  })
}

function bytesEqualConst(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  let diff = 0
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}
