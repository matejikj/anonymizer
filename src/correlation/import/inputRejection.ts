/**
 * T05 — user-facing rejection catalog (what / why / what to do) for import preflight.
 */

import { cs } from '../../i18n/cs.ts'
import type { CompressedFormat } from './decompressInput.ts'

export interface InputRejection {
  readonly code: string
  readonly title: string
  readonly reason: string
  readonly action: string
  readonly detectedType: string
}

/** Single-line message for stores / toasts that only accept a string. */
export function formatInputRejection(r: InputRejection): string {
  return `${r.title} ${r.reason} ${r.action}`
}

function entry(
  code: string,
  block: { title: string; reason: string; action: string; detectedType: string },
): InputRejection {
  return { code, ...block }
}

export function rejectionForUnsupportedCode(code: string): InputRejection {
  const catalog = cs.inputRejection
  switch (code) {
    case 'binary':
      return entry(code, catalog.binary)
    case 'evtx':
      return entry(code, catalog.evtx)
    case 'systemd-journal':
      return entry(code, catalog.systemdJournal)
    case 'etl':
      return entry(code, catalog.etl)
    case 'mime-unsupported':
      return entry(code, catalog.mimeUnsupported)
    case 'too-large':
    case 'per-file-limit':
      return entry(code, catalog.tooLarge)
    case 'too-many-lines':
      return entry(code, catalog.tooManyLines)
    case 'empty':
      return entry(code, catalog.empty)
    case 'unknown-format':
      return entry(code, catalog.unknownFormat)
    case 'read-failed':
      return entry(code, catalog.readFailed)
    case 'gzip-bomb':
      return entry(code, catalog.gzipBomb)
    case 'archive-bomb':
    case 'zip-bomb':
    case 'tar-bomb':
      return entry(code, catalog.zipBomb)
    case 'gzip-corrupt':
    case 'gzip-header-invalid':
    case 'zip-truncated':
    case 'tar-truncated':
    case 'tar-checksum':
    case 'zip-crc':
      return entry(code, catalog.gzipCorrupt)
    case 'gzip-unsupported-api':
    case 'deflate-unsupported-api':
      return entry(code, catalog.gzipUnsupportedApi)
    case 'nested-compression':
      return entry(code, catalog.nestedCompression)
    case 'zip-encrypted':
      return entry(code, catalog.zipEncrypted)
    case 'zip-path':
    case 'tar-path':
      return entry(code, catalog.zipPath)
    case 'zip-zip64':
    case 'zip-unsupported-method':
    case 'zip-too-many-entries':
    case 'tar-too-many-entries':
      return entry(code, catalog.compressedZip)
    case 'tar-unsupported-type':
      return entry(code, catalog.tarUnsupportedType)
    case 'archive-empty-supported':
      return entry(code, catalog.archiveEmptySupported)
    case 'cancelled':
      return entry(code, catalog.cancelled)
    case 'correlation-aggregate-too-large':
    case 'aggregate-too-large':
      return entry('aggregate-too-large', catalog.aggregateTooLarge)
    case 'split-failed':
      return entry(code, catalog.splitFailed)
    default:
      return entry(code, {
        title: catalog.unknownFormat.title,
        reason: catalog.unknownFormat.reason,
        action: catalog.unknownFormat.action,
        detectedType: catalog.unknownFormat.detectedType,
      })
  }
}

export function rejectionForCompressedFormat(format: CompressedFormat): InputRejection {
  const catalog = cs.inputRejection
  switch (format) {
    case 'gzip':
      // Should be inflated before rejection — nested / API failure uses specific codes.
      return entry('compressed-gzip', catalog.compressedGzipUnexpected)
    case 'zip':
      return entry('compressed-zip', catalog.compressedZip)
    case 'xz':
      return entry('compressed-xz', catalog.compressedXz)
    case 'zstd':
      return entry('compressed-zstd', catalog.compressedZstd)
    case 'bzip2':
      return entry('compressed-bzip2', catalog.compressedBzip2)
  }
}
