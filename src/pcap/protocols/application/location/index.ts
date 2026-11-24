/**
 * T53 — shared emergency / location codecs (PIDF-LO, LoST).
 */

export {
  buildPidfLoBodyPlan,
  looksLikePidfContentType,
  looksLikePidfXmlText,
  type LocationBodyOperation,
  type LocationBodySpan,
} from './pidfLoPlan.ts'
export {
  buildLostBodyPlan,
  looksLikeLostContentType,
  looksLikeLostXmlText,
} from './lostPlan.ts'
