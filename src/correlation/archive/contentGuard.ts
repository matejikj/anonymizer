/**
 * T44 — reject private mapping/recovery and obvious credential containers from shareable bundles.
 */

import { MAPPING_BUNDLE_FORMAT } from '../../mapping/bundle/formatConstants.ts'

const RECOVERY_MAGIC = new TextEncoder().encode('RNDPCAPR')
const PEM_PRIVATE = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/

export type BundleContentRejectReason =
  | 'mapping-bundle'
  | 'recovery-bundle'
  | 'private-key'
  | 'binary'

export function classifyForbiddenBundleContent(
  data: Uint8Array,
): BundleContentRejectReason | null {
  if (data.byteLength >= 8) {
    let magic = true
    for (let i = 0; i < 8; i++) {
      if (data[i] !== RECOVERY_MAGIC[i]) {
        magic = false
        break
      }
    }
    if (magic) return 'recovery-bundle'
  }

  // Mapping bundle JSON (format field) — never share inside support ZIP.
  if (data.byteLength > 0 && (data[0] === 0x7b || data[0] === 0x5b)) {
    const head = new TextDecoder('utf-8', { fatal: false }).decode(
      data.subarray(0, Math.min(data.byteLength, 4096)),
    )
    if (head.includes(MAPPING_BUNDLE_FORMAT) || head.includes('rnd-log-anonymizer-mapping-bundle')) {
      return 'mapping-bundle'
    }
  }

  const textSample = new TextDecoder('utf-8', { fatal: false }).decode(
    data.subarray(0, Math.min(data.byteLength, 8192)),
  )
  if (PEM_PRIVATE.test(textSample)) return 'private-key'

  return null
}
