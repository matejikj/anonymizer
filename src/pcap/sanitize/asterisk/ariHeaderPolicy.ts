/**
 * T50 — ARI HTTP header disposition: shared textproto policy table (fail-closed default).
 * Mirrors general HTTP secret protection (Cookie/Authorization/Set-Cookie) and extends
 * for ARI; unknown headers (e.g. X-Private-Token) mask — never bypass HTTP protection.
 */

import type { TextProtoHeaderPolicyTable } from '../../protocols/application/textproto/headerPolicy.ts'

/** Shared HTTP + ARI header policy — defaultAction mask covers unknown ARI/custom headers. */
export const ARI_HTTP_HEADER_POLICY: TextProtoHeaderPolicyTable = {
  protocolId: 'ari-http',
  entries: [
    { name: 'host', action: { kind: 'map', category: 'hostname' } },
    { name: 'content-type', action: { kind: 'structural' } },
    { name: 'content-length', action: { kind: 'structural' } },
    { name: 'transfer-encoding', action: { kind: 'structural' } },
    { name: 'connection', action: { kind: 'structural' } },
    { name: 'accept', action: { kind: 'preserve' } },
    { name: 'accept-encoding', action: { kind: 'preserve' } },
    { name: 'user-agent', action: { kind: 'mask' } },
    { name: 'authorization', action: { kind: 'credential' } },
    { name: 'proxy-authorization', action: { kind: 'credential' } },
    { name: 'cookie', action: { kind: 'credential' } },
    { name: 'set-cookie', action: { kind: 'credential' } },
    // ARI / Asterisk-specific credentials often appear as custom headers
    { name: 'x-asterisk-accountcode', action: { kind: 'mask' } },
  ],
  defaultAction: { kind: 'mask' },
}
