/**
 * Recovery footer at EOF — CRC is an integrity hint, not authentication.
 */

import { sha256 } from '../../../crypto/incrementalSha256'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import { RecoveryReader, RecoveryWriter, writeU32LeTo } from './binaryIO'
import { crc32 } from './crc32'
import {
  RECOVERY_ENCRYPTED_FORMAT_VERSION,
  RECOVERY_ENCRYPTED_UNSUPPORTED_MESSAGE,
  RECOVERY_FOOTER_BYTES,
  RECOVERY_FOOTER_CRC_OFFSET,
  RECOVERY_FORMAT_VERSION,
  RECOVERY_MAGIC_BYTES,
  RECOVERY_SCHEMA_VERSION,
} from './formatConstants'

export interface RecoveryFooter {
  readonly formatVersion: number
  readonly schemaVersion: number
  readonly recoveryId: Uint8Array
  readonly totalByteLength: bigint
  readonly dataFrameCount: number
  readonly indexFrameCount: number
  readonly indexDirectoryOffset: bigint
  readonly indexDirectoryLength: bigint
  readonly finalFrameOffset: bigint
  readonly finalFrameLength: bigint
  readonly anonymizedByteLength: bigint
  readonly anonymizedSha256Prefix64: Uint8Array
  readonly crc32: number
  readonly bytes: Uint8Array
}

export function writeFooter(input: {
  recoveryId: Uint8Array
  totalByteLength: bigint | number
  dataFrameCount: number
  indexFrameCount: number
  indexDirectoryOffset: bigint | number
  indexDirectoryLength: bigint | number
  finalFrameOffset: bigint | number
  finalFrameLength: bigint | number
  anonymizedByteLength: bigint | number
  anonymizedSha256Prefix64: Uint8Array
}): PcapRecoveryResult<Uint8Array> {
  if (input.recoveryId.byteLength !== PCAP_RECOVERY_LIMITS.recoveryIdBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'invalid recoveryId length')
  }
  if (input.anonymizedSha256Prefix64.byteLength !== PCAP_RECOVERY_LIMITS.anonymizedHashPrefixBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'invalid hash prefix length')
  }
  if (input.dataFrameCount > PCAP_RECOVERY_LIMITS.maxDataFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many DATA frames')
  }
  if (input.indexFrameCount > PCAP_RECOVERY_LIMITS.maxIndexFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many INDEX frames')
  }
  const w = new RecoveryWriter()
  w.writeBytes(RECOVERY_MAGIC_BYTES)
  w.writeU16(RECOVERY_FORMAT_VERSION)
  w.writeU16(RECOVERY_SCHEMA_VERSION)
  w.writeBytes(input.recoveryId)
  w.writeU64(input.totalByteLength)
  w.writeU32(input.dataFrameCount)
  w.writeU32(input.indexFrameCount)
  w.writeU64(input.indexDirectoryOffset)
  w.writeU64(input.indexDirectoryLength)
  w.writeU64(input.finalFrameOffset)
  w.writeU64(input.finalFrameLength)
  w.writeU64(input.anonymizedByteLength)
  w.writeBytes(input.anonymizedSha256Prefix64)
  w.writeU32(0)
  w.writeU32(0)
  const bytes = w.toUint8Array()
  if (bytes.byteLength !== RECOVERY_FOOTER_BYTES) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'footer length mismatch')
  }
  const digest = crc32(bytes, 0, RECOVERY_FOOTER_CRC_OFFSET)
  writeU32LeTo(bytes, RECOVERY_FOOTER_CRC_OFFSET, digest)
  return recoveryOk(bytes)
}

export function parseFooter(bytes: Uint8Array): PcapRecoveryResult<RecoveryFooter> {
  if (bytes.byteLength < RECOVERY_FOOTER_BYTES) {
    return recoveryFail(PCAP_RECOVERY_ERROR.footerInvalid, 'footer too short')
  }
  const slice = bytes.byteLength === RECOVERY_FOOTER_BYTES
    ? bytes
    : bytes.subarray(bytes.byteLength - RECOVERY_FOOTER_BYTES)
  const r = new RecoveryReader(slice)
  const magic = r.readBytes(8, 8)
  if (!magic.ok) return recoveryFail(PCAP_RECOVERY_ERROR.footerInvalid, 'truncated footer')
  if (!constEq(magic.value, RECOVERY_MAGIC_BYTES)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.footerInvalid, 'invalid footer magic')
  }
  const formatVersion = r.readU16()
  if (!formatVersion.ok) return formatVersion
  const schemaVersion = r.readU16()
  if (!schemaVersion.ok) return schemaVersion
  if (formatVersion.value === RECOVERY_ENCRYPTED_FORMAT_VERSION) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, RECOVERY_ENCRYPTED_UNSUPPORTED_MESSAGE)
  }
  if (formatVersion.value !== RECOVERY_FORMAT_VERSION || schemaVersion.value !== RECOVERY_SCHEMA_VERSION) {
    return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'unsupported footer version')
  }
  const recoveryId = r.readBytes(PCAP_RECOVERY_LIMITS.recoveryIdBytes, PCAP_RECOVERY_LIMITS.recoveryIdBytes)
  if (!recoveryId.ok) return recoveryId
  const totalByteLength = r.readU64()
  if (!totalByteLength.ok) return totalByteLength
  if (totalByteLength.value > BigInt(PCAP_RECOVERY_LIMITS.maxBundleImportBytes)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'bundle exceeds import limit')
  }
  const dataFrameCount = r.readU32()
  if (!dataFrameCount.ok) return dataFrameCount
  const indexFrameCount = r.readU32()
  if (!indexFrameCount.ok) return indexFrameCount
  if (dataFrameCount.value > PCAP_RECOVERY_LIMITS.maxDataFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many DATA frames')
  }
  if (indexFrameCount.value > PCAP_RECOVERY_LIMITS.maxIndexFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many INDEX frames')
  }
  const indexDirectoryOffset = r.readU64()
  if (!indexDirectoryOffset.ok) return indexDirectoryOffset
  const indexDirectoryLength = r.readU64()
  if (!indexDirectoryLength.ok) return indexDirectoryLength
  const finalFrameOffset = r.readU64()
  if (!finalFrameOffset.ok) return finalFrameOffset
  const finalFrameLength = r.readU64()
  if (!finalFrameLength.ok) return finalFrameLength
  const anonymizedByteLength = r.readU64()
  if (!anonymizedByteLength.ok) return anonymizedByteLength
  const hashPrefix = r.readBytes(
    PCAP_RECOVERY_LIMITS.anonymizedHashPrefixBytes,
    PCAP_RECOVERY_LIMITS.anonymizedHashPrefixBytes,
  )
  if (!hashPrefix.ok) return hashPrefix
  const crc = r.readU32()
  if (!crc.ok) return crc
  const reserved = r.readU32()
  if (!reserved.ok) return reserved
  if (reserved.value !== 0) {
    return recoveryFail(PCAP_RECOVERY_ERROR.footerInvalid, 'reserved bytes must be zero')
  }
  const expectedCrc = crc32(slice, 0, RECOVERY_FOOTER_CRC_OFFSET)
  if (expectedCrc !== crc.value) {
    return recoveryFail(PCAP_RECOVERY_ERROR.footerInvalid, 'footer crc mismatch')
  }
  return recoveryOk({
    formatVersion: formatVersion.value,
    schemaVersion: schemaVersion.value,
    recoveryId: recoveryId.value,
    totalByteLength: totalByteLength.value,
    dataFrameCount: dataFrameCount.value,
    indexFrameCount: indexFrameCount.value,
    indexDirectoryOffset: indexDirectoryOffset.value,
    indexDirectoryLength: indexDirectoryLength.value,
    finalFrameOffset: finalFrameOffset.value,
    finalFrameLength: finalFrameLength.value,
    anonymizedByteLength: anonymizedByteLength.value,
    anonymizedSha256Prefix64: hashPrefix.value,
    crc32: crc.value,
    bytes: slice.slice(),
  })
}

export function footerSha256(footerBytes: Uint8Array): Uint8Array {
  return sha256(footerBytes)
}

function constEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false
  let diff = 0
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}
