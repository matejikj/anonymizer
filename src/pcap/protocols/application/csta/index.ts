/**
 * T49 — CSTA Phase III / uaCSTA (ECMA-323 XML subset).
 */

export {
  looksLikeCstaXmlText,
  looksLikeCstaContentType,
  buildCstaXmlBodyPlan,
  cstaIdentityScopeForUaCsta,
  type CstaBodyOperation,
  type CstaBodySpan,
} from './xmlPlan.ts'
export {
  extractCstaServiceFacts,
  type CstaServiceFacts,
  type CstaServiceKind,
} from './cstaXmlFacts.ts'
export {
  parseAnnexJUnits,
  looksLikeCstaAnnexJ,
  looksLikeBareCstaXml,
  type AnnexJUnit,
} from './annexJFramer.ts'
