/**
 * T15 — declarative header disposition table (fail-closed default: mask).
 */

import type { IdentityCategory } from '../../../../mapping/identityCategories'

export type TextProtoHeaderAction =
  | { readonly kind: 'map'; readonly category: IdentityCategory }
  | { readonly kind: 'mask' }
  | { readonly kind: 'preserve' }
  | { readonly kind: 'detectors' }
  | { readonly kind: 'structural' }
  | { readonly kind: 'credential' }

export interface TextProtoHeaderPolicyEntry {
  readonly name: string
  readonly action: TextProtoHeaderAction
}

export interface TextProtoHeaderPolicyTable {
  readonly protocolId: string
  readonly entries: readonly TextProtoHeaderPolicyEntry[]
  /** Default when header name is unknown — always mask (fail-closed). */
  readonly defaultAction?: TextProtoHeaderAction
}

/**
 * Resolve disposition for a header name (case-insensitive).
 * Unknown headers → mask unless table overrides default.
 */
export function dispositionForTextProtoHeader(
  table: TextProtoHeaderPolicyTable,
  headerName: string,
): TextProtoHeaderAction {
  const key = headerName.trim().toLowerCase()
  for (const entry of table.entries) {
    if (entry.name === key) return entry.action
  }
  return table.defaultAction ?? { kind: 'mask' }
}
