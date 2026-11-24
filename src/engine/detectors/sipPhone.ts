import type { LineIndex } from '../lineIndex.ts'
import type { DetectorConfig, RawMatch } from '../../domain/types.ts'
import { PRIORITY } from '../../domain/types.ts'
import { normalizeSipPhone } from '../normalize.ts'

/**
 * SIP / tel user parts (ARCHITECTURE §7.1).
 * Emits match only for the user identity; host stays for IP/hostname detectors.
 */
const SIP_USER = /(?<![A-Za-z0-9_])sip:([^@;\s>"']+)@/gi
const TEL_USER = /(?<![A-Za-z0-9_])tel:(\+?[0-9][0-9\-()]{3,})/gi

export function detectSipPhones(
  text: string,
  lineIndex: LineIndex,
  _config?: DetectorConfig,
): RawMatch[] {
  const out: RawMatch[] = []
  const seen = new Set<string>()

  SIP_USER.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = SIP_USER.exec(text)) !== null) {
    const user = m[1]!
    // Numeric / phone-like SIP users → sip-phone; login-style left to user-id.
    if (!isSipPhoneUser(user)) continue
    const full = m[0]
    const start = m.index + full.indexOf(user)
    const end = start + user.length
    const key = `${start}:${end}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({
      start,
      end,
      line: lineIndex.lineAt(start),
      category: 'sip-phone',
      original: user,
      normalized: normalizeSipPhone(user),
      detectorId: 'builtin.sipPhone',
      priority: PRIORITY.sipPhone,
      confidence: 1,
    })
  }

  TEL_USER.lastIndex = 0
  while ((m = TEL_USER.exec(text)) !== null) {
    const user = m[1]!
    const full = m[0]
    const start = m.index + full.indexOf(user)
    const end = start + user.length
    const key = `${start}:${end}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({
      start,
      end,
      line: lineIndex.lineAt(start),
      category: 'sip-phone',
      original: user,
      normalized: normalizeSipPhone(user),
      detectorId: 'builtin.sipPhone',
      priority: PRIORITY.sipPhone,
      confidence: 1,
    })
  }

  return out
}

function isSipPhoneUser(user: string): boolean {
  // Digits with optional + and separators; reject pure login names like disp5.
  const digits = user.replace(/[+\-()]/g, '')
  if (!/^\d{3,}$/.test(digits)) return false
  if (/^[A-Za-z]/.test(user)) return false
  return true
}
