/**
 * Enterprise step 10 — TLS handshake branch vocabulary for coverage + report.
 * Branches are protocol-state facts, not entropy guesses.
 */

export const TLS_HANDSHAKE_BRANCHES = ['tls-1.2', 'tls-1.3', 'ech'] as const

export type TlsHandshakeBranch = (typeof TLS_HANDSHAKE_BRANCHES)[number]

/** Issue token pushed onto PacketSanitizationResult.issues (safe — no identities). */
export function tlsBranchIssue(branch: TlsHandshakeBranch): string {
  return `tls-branch:${branch}`
}

export function parseTlsBranchIssue(issue: string): TlsHandshakeBranch | null {
  if (issue === 'tls-branch:tls-1.2' || issue === 'tls-branch:1.2') return 'tls-1.2'
  if (issue === 'tls-branch:tls-1.3' || issue === 'tls-branch:1.3') return 'tls-1.3'
  if (issue === 'tls-branch:ech' || issue === 'tls-branch:tls-ech') return 'ech'
  return null
}

/** Coverage protocol ids that mark an explicit branch (in addition to tls-clienthello/…). */
export const TLS_BRANCH_PROTOCOL_IDS = ['tls-1.2', 'tls-1.3', 'tls-ech'] as const

export type TlsBranchProtocolId = (typeof TLS_BRANCH_PROTOCOL_IDS)[number]

export function branchFromProtocol(protocol: string): TlsHandshakeBranch | null {
  if (protocol === 'tls-1.2') return 'tls-1.2'
  if (protocol === 'tls-1.3') return 'tls-1.3'
  if (protocol === 'tls-ech') return 'ech'
  return null
}

export interface TlsHandlingSummary {
  /** Distinct branches observed in this export / sanitize pass. */
  readonly branches: readonly TlsHandshakeBranch[]
  readonly hasTls12: boolean
  readonly hasTls13: boolean
  readonly hasEch: boolean
}

export function summarizeTlsHandling(input: {
  readonly coverage?: readonly { readonly protocol: string }[]
  readonly issues?: readonly string[]
  readonly protocolCoverage?: readonly { readonly protocol: string }[]
}): TlsHandlingSummary {
  const found = new Set<TlsHandshakeBranch>()

  for (const span of input.coverage ?? []) {
    const b = branchFromProtocol(span.protocol)
    if (b) found.add(b)
  }
  for (const row of input.protocolCoverage ?? []) {
    const b = branchFromProtocol(row.protocol)
    if (b) found.add(b)
  }
  for (const issue of input.issues ?? []) {
    const b = parseTlsBranchIssue(issue)
    if (b) found.add(b)
  }

  const branches = TLS_HANDSHAKE_BRANCHES.filter((b) => found.has(b))
  return {
    branches,
    hasTls12: found.has('tls-1.2'),
    hasTls13: found.has('tls-1.3'),
    hasEch: found.has('ech'),
  }
}
