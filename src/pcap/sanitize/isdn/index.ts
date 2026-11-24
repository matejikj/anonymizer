/**
 * T51 — ISDN DSS1 / LAPD / Q.931 / IUA sanitizers.
 */

export {
  LINKTYPE_LINUX_LAPD,
  looksLikeLapd,
  sanitizeLapd,
  sanitizeLinuxLapdLink,
} from './lapd.ts'
export { Q931_PD, looksLikeQ931, sanitizeQ931 } from './q931.ts'
export { PPID_IUA, IUA_SCTP_PORT, looksLikeIua, sanitizeIua } from './iua.ts'
