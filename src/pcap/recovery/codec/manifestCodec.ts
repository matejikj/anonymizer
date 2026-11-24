/**
 * Encrypted FINAL manifest (plaintext layout). Length-prefixed strings checked first.
 */

import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import type {
  PcapRecoveryLookupEncoding,
  PcapRecoveryManifestV1,
  PcapRecoveryRestoreEncoding,
} from '../domain/types'
import { isPcapAnonymizationLevel, type PcapAnonymizationLevel } from '../../profile/pcapAnonymizationLevel'
import { RecoveryReader, RecoveryWriter } from './binaryIO'

const FORMAT_PCAP = 1
const FORMAT_PCAPNG = 2
const LEVEL_DIAGNOSTIC = 1
const LEVEL_HIGH_PRIVACY = 2
const RESTORE_FULL_LITERAL = 1
const RESTORE_COPY_ANON = 2
const LOOKUP_COMPACT_V1 = 1

export function writeManifest(manifest: PcapRecoveryManifestV1): PcapRecoveryResult<Uint8Array> {
  const nameBytes = new TextEncoder().encode(manifest.originalFileName)
  if (nameBytes.byteLength > PCAP_RECOVERY_LIMITS.maxOriginalFileNameBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'original filename exceeds limit')
  }
  const engineBytes = new TextEncoder().encode(manifest.engineVersion)
  if (engineBytes.byteLength > PCAP_RECOVERY_LIMITS.maxEngineVersionBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'engineVersion exceeds limit')
  }
  if (manifest.recoveryId.byteLength !== PCAP_RECOVERY_LIMITS.recoveryIdBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'invalid recoveryId length')
  }
  if (
    manifest.originalSha256.byteLength !== PCAP_RECOVERY_LIMITS.sha256Bytes
    || manifest.anonymizedSha256.byteLength !== PCAP_RECOVERY_LIMITS.sha256Bytes
    || manifest.indexSha256.byteLength !== PCAP_RECOVERY_LIMITS.sha256Bytes
    || manifest.footerSha256.byteLength !== PCAP_RECOVERY_LIMITS.sha256Bytes
  ) {
    return recoveryFail(PCAP_RECOVERY_ERROR.internal, 'invalid sha256 length')
  }
  if (manifest.policyHash.byteLength > 64) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'policyHash exceeds limit')
  }
  if (manifest.dataFrameCount > PCAP_RECOVERY_LIMITS.maxDataFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many DATA frames')
  }
  if (manifest.indexFrameCount > PCAP_RECOVERY_LIMITS.maxIndexFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many INDEX frames')
  }

  const w = new RecoveryWriter()
  w.writeBytes(manifest.recoveryId)
  w.writeU16(nameBytes.byteLength)
  w.writeBytes(nameBytes)
  w.writeU8(manifest.originalFormat === 'pcapng' ? FORMAT_PCAPNG : FORMAT_PCAP)
  w.writeU64(manifest.originalByteLength)
  w.writeBytes(manifest.originalSha256)
  w.writeU64(manifest.anonymizedByteLength)
  w.writeBytes(manifest.anonymizedSha256)
  w.writeU8(manifest.pcapLevel === 'high-privacy' ? LEVEL_HIGH_PRIVACY : LEVEL_DIAGNOSTIC)
  w.writeU8(manifest.policyHash.byteLength)
  w.writeBytes(manifest.policyHash)
  w.writeU8(engineBytes.byteLength)
  w.writeBytes(engineBytes)
  w.writeU8(restoreEncodingId(manifest.restoreEncoding))
  w.writeU8(lookupEncodingId(manifest.lookupEncoding))
  w.writeU32(manifest.dataFrameCount)
  w.writeU32(manifest.indexFrameCount)
  w.writeU64(manifest.lookupEntryCount)
  w.writeU64(manifest.occurrenceCount)
  w.writeU64(manifest.originalPacketCount)
  w.writeU64(manifest.anonymizedPacketCount)
  w.writeBytes(manifest.indexSha256)
  w.writeBytes(manifest.footerSha256)
  const bytes = w.toUint8Array()
  if (bytes.byteLength > PCAP_RECOVERY_LIMITS.maxManifestPlaintextBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'manifest exceeds limit')
  }
  return recoveryOk(bytes)
}

export function parseManifest(bytes: Uint8Array): PcapRecoveryResult<PcapRecoveryManifestV1> {
  if (bytes.byteLength > PCAP_RECOVERY_LIMITS.maxManifestPlaintextBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'manifest exceeds limit')
  }
  const r = new RecoveryReader(bytes)
  const recoveryId = r.readBytes(PCAP_RECOVERY_LIMITS.recoveryIdBytes, PCAP_RECOVERY_LIMITS.recoveryIdBytes)
  if (!recoveryId.ok) return recoveryId
  const nameLen = r.readU16()
  if (!nameLen.ok) return nameLen
  const originalFileName = r.readUtf8(nameLen.value, PCAP_RECOVERY_LIMITS.maxOriginalFileNameBytes)
  if (!originalFileName.ok) return originalFileName
  const formatId = r.readU8()
  if (!formatId.ok) return formatId
  const originalFormat = decodeFormat(formatId.value)
  if (!originalFormat.ok) return originalFormat
  const originalByteLength = r.readU64()
  if (!originalByteLength.ok) return originalByteLength
  const originalSha256 = r.readBytes(PCAP_RECOVERY_LIMITS.sha256Bytes, PCAP_RECOVERY_LIMITS.sha256Bytes)
  if (!originalSha256.ok) return originalSha256
  const anonymizedByteLength = r.readU64()
  if (!anonymizedByteLength.ok) return anonymizedByteLength
  const anonymizedSha256 = r.readBytes(PCAP_RECOVERY_LIMITS.sha256Bytes, PCAP_RECOVERY_LIMITS.sha256Bytes)
  if (!anonymizedSha256.ok) return anonymizedSha256
  const levelId = r.readU8()
  if (!levelId.ok) return levelId
  const pcapLevel = decodeLevel(levelId.value)
  if (!pcapLevel.ok) return pcapLevel
  const policyLen = r.readU8()
  if (!policyLen.ok) return policyLen
  const policyHash = r.readBytes(policyLen.value, 64)
  if (!policyHash.ok) return policyHash
  const engineLen = r.readU8()
  if (!engineLen.ok) return engineLen
  const engineVersion = r.readUtf8(engineLen.value, PCAP_RECOVERY_LIMITS.maxEngineVersionBytes)
  if (!engineVersion.ok) return engineVersion
  const restoreId = r.readU8()
  if (!restoreId.ok) return restoreId
  const restoreEncoding = decodeRestore(restoreId.value)
  if (!restoreEncoding.ok) return restoreEncoding
  const lookupId = r.readU8()
  if (!lookupId.ok) return lookupId
  const lookupEncoding = decodeLookup(lookupId.value)
  if (!lookupEncoding.ok) return lookupEncoding
  const dataFrameCount = r.readU32()
  if (!dataFrameCount.ok) return dataFrameCount
  const indexFrameCount = r.readU32()
  if (!indexFrameCount.ok) return indexFrameCount
  const lookupEntryCount = r.readU64()
  if (!lookupEntryCount.ok) return lookupEntryCount
  const occurrenceCount = r.readU64()
  if (!occurrenceCount.ok) return occurrenceCount
  const originalPacketCount = r.readU64()
  if (!originalPacketCount.ok) return originalPacketCount
  const anonymizedPacketCount = r.readU64()
  if (!anonymizedPacketCount.ok) return anonymizedPacketCount
  const indexSha256 = r.readBytes(PCAP_RECOVERY_LIMITS.sha256Bytes, PCAP_RECOVERY_LIMITS.sha256Bytes)
  if (!indexSha256.ok) return indexSha256
  const footerSha256 = r.readBytes(PCAP_RECOVERY_LIMITS.sha256Bytes, PCAP_RECOVERY_LIMITS.sha256Bytes)
  if (!footerSha256.ok) return footerSha256
  const consumed = r.expectConsumed()
  if (!consumed.ok) return consumed
  if (dataFrameCount.value > PCAP_RECOVERY_LIMITS.maxDataFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many DATA frames')
  }
  if (indexFrameCount.value > PCAP_RECOVERY_LIMITS.maxIndexFrames) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'too many INDEX frames')
  }
  return recoveryOk({
    recoveryId: recoveryId.value,
    originalFileName: originalFileName.value,
    originalFormat: originalFormat.value,
    originalByteLength: originalByteLength.value,
    originalSha256: originalSha256.value,
    anonymizedByteLength: anonymizedByteLength.value,
    anonymizedSha256: anonymizedSha256.value,
    pcapLevel: pcapLevel.value,
    policyHash: policyHash.value,
    engineVersion: engineVersion.value,
    restoreEncoding: restoreEncoding.value,
    lookupEncoding: lookupEncoding.value,
    dataFrameCount: dataFrameCount.value,
    indexFrameCount: indexFrameCount.value,
    lookupEntryCount: lookupEntryCount.value,
    occurrenceCount: occurrenceCount.value,
    originalPacketCount: originalPacketCount.value,
    anonymizedPacketCount: anonymizedPacketCount.value,
    indexSha256: indexSha256.value,
    footerSha256: footerSha256.value,
  })
}

function restoreEncodingId(enc: PcapRecoveryRestoreEncoding): number {
  return enc === 'copy-anonymized-literal-v1' ? RESTORE_COPY_ANON : RESTORE_FULL_LITERAL
}

function lookupEncodingId(enc: PcapRecoveryLookupEncoding): number {
  return enc === 'compact-index-v1' ? LOOKUP_COMPACT_V1 : 0
}

function decodeFormat(id: number): PcapRecoveryResult<'pcap' | 'pcapng'> {
  if (id === FORMAT_PCAP) return recoveryOk('pcap')
  if (id === FORMAT_PCAPNG) return recoveryOk('pcapng')
  return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'unknown original format')
}

function decodeLevel(id: number): PcapRecoveryResult<PcapAnonymizationLevel> {
  const level = id === LEVEL_HIGH_PRIVACY ? 'high-privacy' : id === LEVEL_DIAGNOSTIC ? 'diagnostic' : null
  if (!level || !isPcapAnonymizationLevel(level)) {
    return recoveryFail(PCAP_RECOVERY_ERROR.invalidFormat, 'unknown pcap level')
  }
  return recoveryOk(level)
}

function decodeRestore(id: number): PcapRecoveryResult<PcapRecoveryRestoreEncoding> {
  if (id === RESTORE_FULL_LITERAL) return recoveryOk('full-literal-frames-v1')
  if (id === RESTORE_COPY_ANON) return recoveryOk('copy-anonymized-literal-v1')
  return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'unknown restore encoding')
}

function decodeLookup(id: number): PcapRecoveryResult<PcapRecoveryLookupEncoding> {
  if (id === LOOKUP_COMPACT_V1) return recoveryOk('compact-index-v1')
  return recoveryFail(PCAP_RECOVERY_ERROR.versionUnsupported, 'unknown lookup encoding')
}
