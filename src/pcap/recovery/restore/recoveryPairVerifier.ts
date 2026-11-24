/**
 * Plaintext v4 pair verification — prefix is a hint; full hashes detect mismatched files.
 * Hashes do not authenticate an attacker-controlled recovery bundle.
 */

import { IncrementalSha256, bytesEqual } from '../../../crypto/incrementalSha256'
import { feedBlobChunks } from '../../capture/chunkFeeder'
import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import type { RecoveryPairSummary } from '../domain/types'
import {
  openRecoveryBundleBounds,
  type RecoveryBundleBounds,
} from './recoveryBundleReader'

export interface PairPreflightResult {
  readonly bounds: RecoveryBundleBounds | null
  /** Present when the anonymized file was hashed; used for subsequent full pair verification. */
  readonly anonymizedSha256: Uint8Array | null
  readonly summary: RecoveryPairSummary
}

/**
 * Bounded preflight: preamble/footer + incremental anonymized hash.
 * Compares the 64-bit prefix as a pair hint; there is no KDF or passphrase.
 */
export async function preflightRecoveryPair(input: {
  anonymizedBlob: Blob
  recoveryBlob: Blob
  isCancelled?: () => boolean
}): Promise<PcapRecoveryResult<PairPreflightResult>> {
  const anonymizedPresent = input.anonymizedBlob.size > 0
  const recoveryPresent = input.recoveryBlob.size > 0
  if (!anonymizedPresent || !recoveryPresent) {
    return recoveryOk({
      bounds: null,
      anonymizedSha256: null,
      summary: {
        anonymizedPresent,
        recoveryPresent,
        formatVersion: 0,
        schemaVersion: 0,
        anonymizedHashPrefix64: '',
        pairLooksCompatible: false,
      },
    })
  }

  if (input.anonymizedBlob.size > PCAP_RECOVERY_LIMITS.maxBundleImportBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.oversize, 'anonymized file exceeds limit')
  }

  let bounds: RecoveryBundleBounds
  try {
    const opened = await openRecoveryBundleBounds(input.recoveryBlob)
    if (!opened.ok) return opened
    bounds = opened.value
  } catch (err) {
    return recoveryFail(
      PCAP_RECOVERY_ERROR.invalidFormat,
      err instanceof Error ? err.message : 'invalid recovery bundle',
    )
  }

  if (input.isCancelled?.()) {
    return recoveryFail(PCAP_RECOVERY_ERROR.cancelled, 'cancelled')
  }

  const expectedAnonLen = Number(bounds.footer.anonymizedByteLength)
  if (
    Number.isFinite(expectedAnonLen)
    && expectedAnonLen > 0
    && input.anonymizedBlob.size !== expectedAnonLen
  ) {
    return recoveryOk({
      bounds,
      anonymizedSha256: null,
      summary: {
        anonymizedPresent: true,
        recoveryPresent: true,
        formatVersion: bounds.preamble.formatVersion,
        schemaVersion: bounds.preamble.schemaVersion,
        anonymizedHashPrefix64: bounds.anonymizedHashPrefixHex,
        pairLooksCompatible: false,
      },
    })
  }

  const hasher = new IncrementalSha256()
  try {
    await feedBlobChunks(input.anonymizedBlob, (chunk) => {
      if (input.isCancelled?.()) throw new PreflightCancelled()
      hasher.update(chunk)
    })
  } catch (err) {
    if (err instanceof PreflightCancelled) {
      return recoveryFail(PCAP_RECOVERY_ERROR.cancelled, 'cancelled')
    }
    throw err
  }

  const anonymizedSha256 = hasher.digest()
  const prefix = anonymizedSha256.subarray(0, PCAP_RECOVERY_LIMITS.anonymizedHashPrefixBytes)
  const pairLooksCompatible = bytesEqual(prefix, bounds.preamble.anonymizedSha256Prefix64)

  return recoveryOk({
    bounds,
    anonymizedSha256: pairLooksCompatible ? anonymizedSha256 : anonymizedSha256,
    summary: {
      anonymizedPresent: true,
      recoveryPresent: true,
      formatVersion: bounds.preamble.formatVersion,
      schemaVersion: bounds.preamble.schemaVersion,
      anonymizedHashPrefix64: bounds.anonymizedHashPrefixHex,
      pairLooksCompatible,
    },
  })
}

class PreflightCancelled extends Error {
  constructor() {
    super('cancelled')
    this.name = 'PreflightCancelled'
  }
}
