/**
 * Bounded query extractor for pasted AI / diagnostic text (step 7).
 * Shape-based only — no network, no profile rulesets.
 */

import { PCAP_RECOVERY_ERROR, recoveryFail, recoveryOk, type PcapRecoveryResult } from '../domain/errors'
import { PCAP_RECOVERY_LIMITS } from '../domain/limits'
import type { RecoveryLookupCategory, RecoveryQueryCandidate } from '../domain/types'

const IPV4 =
  /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g

const IPV6 =
  /(?<![\w:])(?:(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:)(?![\w:])/gi

const MAC = /(?<![\w:])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![\w:])/gi

const HOSTNAME =
  /(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])/gi

const URI = /\b(?:https?|sips?):\/\/[^\s"'<>]+/gi

const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi

/** SIP Call-ID often looks like token@host or bare UUID-ish. */
const SIP_CALL_ID =
  /(?<![\w@.-])[A-Za-z0-9][A-Za-z0-9_.+-]{2,120}@[A-Za-z0-9][A-Za-z0-9.-]{1,120}(?![\w@.-])/g

const SIP_TOKEN = /\b(?:branch|tag|call-id)\s*[:=]\s*([^\s;,>"']+)/gi

const PORT = /\b(?:port|srcport|dstport)\s*[:=]?\s*(\d{1,5})\b/gi
const VLAN = /\b(?:vlan|vid)\s*[:=]?\s*(\d{1,4})\b/gi

const PACKET_REF = /\b(?:packet|paket|frame)\s*[#:]?\s*(\d{1,9})\b/gi

export interface ExtractQueryResult {
  readonly candidates: readonly RecoveryQueryCandidate[]
  readonly truncated: boolean
}

function pushUnique(
  out: RecoveryQueryCandidate[],
  seen: Set<string>,
  c: RecoveryQueryCandidate,
  max: number,
): boolean {
  if (out.length >= max) return false
  const key =
    c.kind === 'packet'
      ? `p:${c.anonymizedPacketNumber}`
      : `v:${c.categoryHint}:${c.text.toLowerCase()}`
  if (seen.has(key)) return true
  seen.add(key)
  out.push(c)
  return out.length < max
}

function runGlobal(
  re: RegExp,
  text: string,
  onMatch: (m: RegExpExecArray) => RecoveryQueryCandidate | null,
  out: RecoveryQueryCandidate[],
  seen: Set<string>,
  max: number,
): boolean {
  re.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const c = onMatch(m)
    if (!c) continue
    if (!pushUnique(out, seen, c, max)) return false
  }
  return true
}

/**
 * Extract ≤ maxQueryCandidates shapes from query text.
 * Rejects queries larger than maxQueryBytes before any work.
 */
export function extractRecoveryQuery(query: string): PcapRecoveryResult<ExtractQueryResult> {
  if (typeof query !== 'string') {
    return recoveryFail(PCAP_RECOVERY_ERROR.queryInvalid, 'query must be a string')
  }
  const bytes = new TextEncoder().encode(query).byteLength
  if (bytes > PCAP_RECOVERY_LIMITS.maxQueryBytes) {
    return recoveryFail(PCAP_RECOVERY_ERROR.queryInvalid, 'query exceeds size limit')
  }

  const max = PCAP_RECOVERY_LIMITS.maxQueryCandidates
  const out: RecoveryQueryCandidate[] = []
  const seen = new Set<string>()
  let room = true

  room = runGlobal(
    PACKET_REF,
    query,
    (m) => {
      const n = Number(m[1])
      if (!Number.isInteger(n) || n < 1) return null
      return {
        kind: 'packet',
        anonymizedPacketNumber: n,
        start: m.index,
        end: m.index + m[0]!.length,
      }
    },
    out,
    seen,
    max,
  )

  const valueShapes: Array<{
    re: RegExp
    category: RecoveryLookupCategory
    pick?: (m: RegExpExecArray) => string
  }> = [
    { re: IPV4, category: 'ipv4' },
    { re: IPV6, category: 'ipv6' },
    { re: MAC, category: 'mac' },
    { re: URI, category: 'url' },
    { re: EMAIL, category: 'email' },
    { re: HOSTNAME, category: 'hostname' },
    { re: SIP_CALL_ID, category: 'sip-call-id' },
    {
      re: SIP_TOKEN,
      category: 'sip-token',
      pick: (m) => m[1] ?? m[0]!,
    },
    {
      re: PORT,
      category: 'port',
      pick: (m) => m[1] ?? m[0]!,
    },
    {
      re: VLAN,
      category: 'vlan',
      pick: (m) => m[1] ?? m[0]!,
    },
  ]

  for (const shape of valueShapes) {
    if (!room) break
    room = runGlobal(
      shape.re,
      query,
      (m) => {
        const text = (shape.pick ? shape.pick(m) : m[0]!).trim()
        if (!text) return null
        if (shape.category === 'port' || shape.category === 'vlan') {
          const n = Number(text)
          if (!Number.isInteger(n) || n < 0 || (shape.category === 'port' && n > 65535)) return null
          if (shape.category === 'vlan' && n > 4095) return null
        }
        return {
          kind: 'value',
          categoryHint: shape.category,
          text,
          start: m.index,
          end: m.index + m[0]!.length,
        }
      },
      out,
      seen,
      max,
    )
  }

  return recoveryOk({
    candidates: out,
    truncated: !room || out.length >= max,
  })
}

export function normalizeLookupKey(text: string): string {
  return text.trim()
}
