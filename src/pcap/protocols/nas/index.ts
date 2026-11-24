/**
 * T59 — NAS EPS/5GS child codec (standalone; carriers T57/T58/T61 call in).
 */

export {
  looksLikeNas,
  looksLikeNasEps,
  looksLikeNas5gs,
  parseNasFrame,
  EPS_EMM_MSG,
  EPS_ESM_MSG,
  G5MM_MSG,
  G5SM_MSG,
  type NasFrame,
  type NasFamily,
  type NasSecurityClass,
} from './framing.ts'

export {
  parseMobileIdentityValue,
  decodeMobileIdentityDigits,
  normalizeIdentityDigits,
  remapMobileIdentityDigits,
  classifySuciValue,
  type NasIdentityKind,
  type NasIdentityView,
} from './identity.ts'
