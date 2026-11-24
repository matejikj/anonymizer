/**
 * T55 — USP Record / SessionContext / Msg field descriptors (Broadband Forum baseline).
 * Unknown extensions of every wire type use typed unknown → mask; nested walk is depth-bounded.
 */

export const USP_MAX_NESTING_DEPTH = 12

/** Protobuf wire types we accept; others desync. */
export type UspWireType = 0 | 1 | 2 | 5

export type UspFieldPolicy =
  | { readonly kind: 'preserve' }
  | { readonly kind: 'map-id'; readonly prefix: string }
  | { readonly kind: 'mask'; readonly domain: string }
  | { readonly kind: 'nested'; readonly message: UspMessageName }
  | { readonly kind: 'payload-msg' }
  | { readonly kind: 'msg-body' }

export type UspMessageName = 'Record' | 'NoSessionContext' | 'SessionContext' | 'Msg'

export type UspFieldTable = Readonly<Record<number, UspFieldPolicy>>

/**
 * usp-record-*.proto Record message.
 * payload_security (4) is preserved so nested plaintext vs E2E can branch.
 */
export const USP_RECORD_FIELDS: UspFieldTable = {
  1: { kind: 'preserve' }, // version
  2: { kind: 'map-id', prefix: 'usp-ep:' }, // to_id
  3: { kind: 'map-id', prefix: 'usp-ep:' }, // from_id
  4: { kind: 'preserve' }, // payload_security enum
  5: { kind: 'mask', domain: 'usp-auth' }, // mac_signature
  6: { kind: 'mask', domain: 'usp-auth' }, // sender_cert
  7: { kind: 'nested', message: 'NoSessionContext' },
  8: { kind: 'nested', message: 'SessionContext' },
}

export const USP_NO_SESSION_CONTEXT_FIELDS: UspFieldTable = {
  1: { kind: 'payload-msg' }, // payload → Msg
}

/** SessionContext: session_id + sequence/correlation preserve; payload at field 6. */
export const USP_SESSION_CONTEXT_FIELDS: UspFieldTable = {
  1: { kind: 'map-id', prefix: 'usp-sess:' }, // session_id
  2: { kind: 'preserve' }, // sequence_id
  3: { kind: 'preserve' }, // expected_id
  4: { kind: 'preserve' }, // retransmit_id
  5: { kind: 'preserve' }, // payload_security
  6: { kind: 'payload-msg' }, // payload → Msg
}

/** Msg: header/body as nested; unknown numeric/string extensions mask. */
export const USP_MSG_FIELDS: UspFieldTable = {
  1: { kind: 'nested', message: 'Msg' }, // Header — recurse with Msg-like unknown policy
  2: { kind: 'msg-body' }, // Body — harvest/mask strings + unknown wire types
}

export function fieldPolicyFor(message: UspMessageName, field: number): UspFieldPolicy {
  const table =
    message === 'Record'
      ? USP_RECORD_FIELDS
      : message === 'NoSessionContext'
        ? USP_NO_SESSION_CONTEXT_FIELDS
        : message === 'SessionContext'
          ? USP_SESSION_CONTEXT_FIELDS
          : USP_MSG_FIELDS
  return table[field] ?? { kind: 'mask', domain: 'usp-unknown' }
}
