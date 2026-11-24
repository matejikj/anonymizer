/**
 * Canonical bit layout for `.rnd-pcap-recovery` v4 (little-endian).
 *
 * Wire order:
 *   PREAMBLE → plaintext DATA frames → plaintext INDEX frames → plaintext FINAL → FOOTER
 *
 * v4 stores frame payloads in plaintext (no AEAD / passphrase).
 * v3 (AEAD + DEK envelope) and older versions are rejected as unsupported.
 */

import { PCAP_RECOVERY_LIMITS } from '../domain/limits'

/** ASCII magic — distinct from mapping-bundle FourCC. */
export const RECOVERY_MAGIC_ASCII = 'RNDPCAPR' as const
export const RECOVERY_MAGIC_BYTES = new TextEncoder().encode(RECOVERY_MAGIC_ASCII)

export const RECOVERY_FORMAT_VERSION = 4
export const RECOVERY_SCHEMA_VERSION = 4

/** Last AEAD-encrypted format — readers reject with a clear Czech message. */
export const RECOVERY_ENCRYPTED_FORMAT_VERSION = 3

export const RECOVERY_FRAME_TYPE_DATA = 1
export const RECOVERY_FRAME_TYPE_INDEX = 2
export const RECOVERY_FRAME_TYPE_FINAL = 3

export const RECOVERY_FRAME_FLAG_NONE = 0
/** Reserved for a later release; v4 writers must leave unset, readers reject if mandatory. */
export const RECOVERY_FRAME_FLAG_COMPRESSED = 1

export const RECOVERY_MANDATORY_FLAGS_NONE = 0
export const RECOVERY_OPTIONAL_FLAGS_NONE = 0

/**
 * Fixed preamble layout (publicHeader — no crypto material).
 *
 *  Offset  Size  Field
 *  0       8     magic "RNDPCAPR"
 *  8       2     formatVersion
 *  10      2     schemaVersion
 *  12      2     headerLength
 *  14      2     mandatoryFlags
 *  16      2     optionalFlags
 *  18      2     reserved0 (must be 0)
 *  20      16    recoveryId
 *  36      8     anonymizedSha256Prefix64 (pair hint only — not auth)
 */
export const RECOVERY_PREAMBLE_LENGTH = 44

/**
 * Frame envelope (before plaintext payload):
 *  frameType          u8
 *  frameFlags         u8
 *  reserved           u16  must be 0
 *  frameIndex         u32
 *  plaintextLength    u32
 *  payloadLength      u32  (== plaintextLength for v4 plaintext frames)
 *  payload            payloadLength bytes
 */
export const RECOVERY_FRAME_HEADER_BYTES = 16

export function recoveryFrameWireSize(payloadLength: number): number {
  return RECOVERY_FRAME_HEADER_BYTES + payloadLength
}

/**
 * Fixed footer at EOF (direct access from end of file):
 *  0   8   magic "RNDPCAPR"
 *  8   2   formatVersion
 *  10  2   schemaVersion
 *  12  16  recoveryId
 *  28  8   totalByteLength (u64)
 *  36  4   dataFrameCount
 *  40  4   indexFrameCount
 *  44  8   indexDirectoryOffset (u64)
 *  52  8   indexDirectoryLength (u64)
 *  60  8   finalFrameOffset (u64)
 *  68  8   finalFrameLength (u64)
 *  76  8   anonymizedByteLength (u64)
 *  84  8   anonymizedSha256Prefix64
 *  92  4   crc32 (integrity hint only — not authentication)
 *  96  4   reserved (must be 0)
 */
export const RECOVERY_FOOTER_BYTES = 100
export const RECOVERY_FOOTER_MAGIC_OFFSET = 0
export const RECOVERY_FOOTER_CRC_OFFSET = 92

export const RECOVERY_FILE_EXTENSION = PCAP_RECOVERY_LIMITS.fileExtension

/** Per-DATA-frame restore-op stream (copy-anonymized-literal-v1). */
export const RECOVERY_RESTORE_OPS_MAGIC_ASCII = 'RCOPS001' as const
export const RECOVERY_RESTORE_OPS_MAGIC = new TextEncoder().encode(RECOVERY_RESTORE_OPS_MAGIC_ASCII)
export const RECOVERY_OP_LITERAL = 1
export const RECOVERY_OP_COPY_ANON = 2
/** magic(8) + opCount(u32) */
export const RECOVERY_RESTORE_OPS_FRAME_HEADER_BYTES = 12
/** type + originalOffset + length + anonymizedOffset */
export const RECOVERY_OP_COPY_ANON_BYTES = 13
/** type + originalOffset + length (payload follows) */
export const RECOVERY_OP_LITERAL_HEADER_BYTES = 9

/** User-facing rejection for legacy AEAD recovery bundles. */
export const RECOVERY_ENCRYPTED_UNSUPPORTED_MESSAGE =
  'Šifrované recovery už není podporováno'
