/**
 * T23 — LDAP / CLDAP sanitizer (RFC 4511 BER): map DN/attrs, mask passwords, NTLMSSP via T16.
 */

import type { MappingLike } from '../anonymization/mapping'
import type { IntentCollector } from '../discovery/intentCollector'
import type { PatchCollector } from './PatchCollector'
import type { AppLayerResult, LayerCoverage } from './types'
import type { IdentityCategory } from '../../mapping/identityCategories'
import { walkBer, type BerNode } from '../protocols/application/binproto'
import { looksLikeNtlmssp, sanitizeNtlmssp } from '../protocols/application/binproto'
import { createProtocolNeutralMaskFill } from './maskFill'
import { computeFixedLengthAsciiBytes } from './textPatch'
import { canonicalizeIdentity } from '../../mapping/canonicalize'
import { deferredTextMapMeta } from './deferredMapMeta.ts'

const LDAP_PORTS = new Set([389, 3268])
const ASN1_OCTET_STRING = 0x04
const ASN1_INTEGER = 0x02
const ASN1_ENUMERATED = 0x0a
const ASN1_SEQUENCE = 0x10
const ASN1_SET = 0x11
const ASN1_BOOLEAN = 0x01

const PASSWORD_ATTRS = new Set([
  'userpassword',
  'unicodepwd',
  'supplementalcredentials',
  'ms-mcs-admpwd',
])

const ATTR_CATEGORY: Readonly<Record<string, IdentityCategory>> = {
  mail: 'email',
  userprincipalname: 'email',
  samaccountname: 'user-id',
  uid: 'user-id',
  cn: 'person',
  displayname: 'person',
  givenname: 'person',
  sn: 'person',
  telephonenumber: 'sip-phone',
  mobile: 'sip-phone',
  ipphone: 'sip-phone',
  dnshostname: 'hostname',
}

export function isLdapPortHint(src: number, dst: number): boolean {
  return LDAP_PORTS.has(src) || LDAP_PORTS.has(dst)
}

export function looksLikeLdap(data: Uint8Array, offset: number, length: number): boolean {
  if (length < 6 || data[offset] !== 0x30) return false
  const { roots } = walkBer(data, offset, length, { maxDepth: 4, maxNodes: 32 })
  const root = roots[0]
  if (!root || root.children.length < 2) return false
  // messageID INTEGER + APPLICATION-tagged protocolOp (RFC 4511 CHOICE)
  const mid = root.children[0]!
  const op = root.children[1]!
  return mid.tag.number === ASN1_INTEGER && op.tag.tagClass === 'application'
}

export function sanitizeLdap(
  buffer: Uint8Array,
  offset: number,
  length: number,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): AppLayerResult | null {
  if (!looksLikeLdap(buffer, offset, length)) return null
  const coverage: LayerCoverage[] = []
  const issues: string[] = []
  const { roots, issues: berIssues } = walkBer(buffer, offset, length, { maxDepth: 32, maxNodes: 2048 })
  for (const i of berIssues) issues.push(`ldap-${i.code}`)

  if (roots.length === 0) {
    mask(collector, intents, packetIndex, offset, length, 'ldap-malformed')
    coverage.push({ protocol: 'ldap', offset, length, status: 'malformed' })
    return { coverage, issues }
  }

  for (const msg of roots) {
    sanitizeMessage(buffer, msg, collector, mapping, intents, packetIndex, issues)
  }
  coverage.push({ protocol: 'ldap', offset, length, status: 'covered' })
  return { coverage, issues }
}

function sanitizeMessage(
  buffer: Uint8Array,
  msg: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  const op = msg.children[1]
  if (!op || op.tag.tagClass !== 'application') {
    walkSensitive(buffer, msg, collector, mapping, intents, packetIndex, issues)
    return
  }
  switch (op.tag.number) {
    case 0: // bindRequest
      sanitizeBindRequest(buffer, op, collector, mapping, intents, packetIndex, issues)
      break
    case 1: // bindResponse
      sanitizeResult(buffer, op, collector, mapping, intents, packetIndex, issues)
      break
    case 3: // searchRequest
      sanitizeSearchRequest(buffer, op, collector, mapping, intents, packetIndex, issues)
      break
    case 4: // searchResEntry
      sanitizeSearchEntry(buffer, op, collector, mapping, intents, packetIndex, issues)
      break
    case 5: // searchResDone
    case 7: // modifyResponse
    case 9: // addResponse
    case 11: // delResponse
    case 13: // modDNResponse
    case 15: // compareResponse
    case 19: // extendedResp
      sanitizeResult(buffer, op, collector, mapping, intents, packetIndex, issues)
      break
    default:
      walkSensitive(buffer, op, collector, mapping, intents, packetIndex, issues)
  }
}

function sanitizeBindRequest(
  buffer: Uint8Array,
  op: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  // APPLICATION 0 wraps SEQUENCE { version, name, authentication }
  const kids = op.children
  const name = kids.find((c) => !c.tag.constructed && c.tag.number === ASN1_OCTET_STRING)
  if (name) sanitizeDnOrText(buffer, name, collector, mapping, intents, packetIndex)
  const auth = kids.find((c) => c.tag.tagClass === 'context')
  if (!auth) return
  if (auth.tag.number === 0) {
    // simple [0] OCTET STRING — always mask password bytes
    maskContent(buffer, auth, collector, intents, packetIndex, 'ldap-bind-password')
  } else if (auth.tag.number === 3) {
    const mech = auth.children[0]
    const creds = auth.children[1]
    void mech
    if (creds && isOctet(creds)) {
      if (looksLikeNtlmssp(buffer, creds.contentOffset, creds.contentLength)) {
        sanitizeNtlmssp(buffer, creds.contentOffset, creds.contentLength, collector, mapping, intents, packetIndex)
      } else {
        maskContent(buffer, creds, collector, intents, packetIndex, 'ldap-sasl-creds')
        issues.push('ldap-sasl-opaque')
      }
    }
  }
}

function sanitizeResult(
  buffer: Uint8Array,
  op: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  // SEQUENCE { resultCode ENUM, matchedDN, diagnosticMessage, ... }
  const seq = firstSequence(op)
  if (!seq || seq.children.length < 3) {
    walkSensitive(buffer, op, collector, mapping, intents, packetIndex, issues)
    return
  }
  // resultCode preserve (ENUMERATED / INTEGER)
  const matched = seq.children[1]!
  const diag = seq.children[2]!
  if (isOctet(matched)) sanitizeDnOrText(buffer, matched, collector, mapping, intents, packetIndex)
  if (isOctet(diag) && diag.contentLength > 0) {
    maskContent(buffer, diag, collector, intents, packetIndex, 'ldap-diagnostic')
  }
}

function sanitizeSearchRequest(
  buffer: Uint8Array,
  op: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  const seq = firstSequence(op)
  if (!seq || seq.children.length < 7) {
    walkSensitive(buffer, op, collector, mapping, intents, packetIndex, issues)
    return
  }
  const base = seq.children[0]!
  if (isOctet(base)) sanitizeDnOrText(buffer, base, collector, mapping, intents, packetIndex)
  // scope, deref, size, time, typesOnly preserved
  const filter = seq.children[6]!
  sanitizeFilter(buffer, filter, collector, mapping, intents, packetIndex, issues)
  // attributes SEQUENCE OF LDAPString — preserve names
}

function sanitizeSearchEntry(
  buffer: Uint8Array,
  op: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  const seq = firstSequence(op)
  if (!seq || seq.children.length < 1) {
    walkSensitive(buffer, op, collector, mapping, intents, packetIndex, issues)
    return
  }
  const objectName = seq.children[0]!
  if (isOctet(objectName)) sanitizeDnOrText(buffer, objectName, collector, mapping, intents, packetIndex)
  const attrs = seq.children[1]
  if (!attrs) return
  for (const partial of attrs.children) {
    // PartialAttribute ::= SEQUENCE { type, vals SET OF }
    const typeNode = partial.children[0]
    const vals = partial.children[1]
    if (!typeNode || !isOctet(typeNode) || !vals) continue
    const attrName = latin1(buffer, typeNode.contentOffset, typeNode.contentLength).toLowerCase()
    for (const val of vals.children) {
      if (!isOctet(val)) continue
      if (PASSWORD_ATTRS.has(attrName) || attrName.includes('password') || attrName.includes('credential')) {
        maskContent(buffer, val, collector, intents, packetIndex, 'ldap-password-attr')
        continue
      }
      if (attrName === 'objectsid' || attrName === 'objectguid') {
        mapOpaqueBinary(buffer, val, collector, mapping, intents, packetIndex)
        continue
      }
      if (
        attrName === 'jpegphoto'
        || attrName === 'thumbnailphoto'
        || attrName === 'usercertificate'
      ) {
        maskContent(buffer, val, collector, intents, packetIndex, 'ldap-binary-attr')
        continue
      }
      const cat = ATTR_CATEGORY[attrName]
      if (cat) {
        mapOctetCategory(buffer, val, cat, collector, mapping, intents, packetIndex)
      } else if (looksLikeDn(latin1(buffer, val.contentOffset, val.contentLength))) {
        sanitizeDnOrText(buffer, val, collector, mapping, intents, packetIndex)
      } else {
        maskContent(buffer, val, collector, intents, packetIndex, 'ldap-unknown-attr')
      }
    }
  }
}

function sanitizeFilter(
  buffer: Uint8Array,
  filter: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  // Filter CHOICE — walk AssertionValue OCTET STRINGs; AttributeDescription preserve
  const visit = (node: BerNode): void => {
    if (node.tag.tagClass === 'context' && !node.tag.constructed) {
      // present [7] AttributeDescription — preserve
      return
    }
    if (
      node.tag.tagClass === 'context'
      && node.tag.constructed
      && (node.tag.number === 3 || node.tag.number === 4 || node.tag.number === 5 || node.tag.number === 6 || node.tag.number === 8 || node.tag.number === 9)
    ) {
      // equality/substr/gte/lte/approx/extensible — type then value(s)
      const typeNode = node.children[0]
      const attrName = typeNode && isOctet(typeNode)
        ? latin1(buffer, typeNode.contentOffset, typeNode.contentLength).toLowerCase()
        : ''
      for (let i = 1; i < node.children.length; i++) {
        const c = node.children[i]!
        if (isOctet(c)) {
          if (PASSWORD_ATTRS.has(attrName) || attrName.includes('password')) {
            maskContent(buffer, c, collector, intents, packetIndex, 'ldap-filter-password')
          } else {
            const cat = ATTR_CATEGORY[attrName]
            if (cat) mapOctetCategory(buffer, c, cat, collector, mapping, intents, packetIndex)
            else maskContent(buffer, c, collector, intents, packetIndex, 'ldap-filter-value')
          }
        } else if (c.tag.constructed) {
          // substrings SEQUENCE
          for (const sub of c.children) {
            if (isOctet(sub) && sub.tag.tagClass === 'context') {
              const cat = ATTR_CATEGORY[attrName]
              if (cat) mapOctetCategory(buffer, sub, cat, collector, mapping, intents, packetIndex)
              else maskContent(buffer, sub, collector, intents, packetIndex, 'ldap-filter-substr')
            }
          }
        }
      }
      return
    }
    for (const c of node.children) visit(c)
  }
  visit(filter)
  void issues
}

function walkSensitive(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
  issues: string[],
): void {
  if (!node.tag.constructed && node.tag.number === ASN1_OCTET_STRING && node.contentLength > 0) {
    if (looksLikeNtlmssp(buffer, node.contentOffset, node.contentLength)) {
      sanitizeNtlmssp(buffer, node.contentOffset, node.contentLength, collector, mapping, intents, packetIndex)
      return
    }
    const text = latin1(buffer, node.contentOffset, node.contentLength)
    if (looksLikeDn(text)) {
      sanitizeDnOrText(buffer, node, collector, mapping, intents, packetIndex)
      return
    }
    // Unknown octet — fail-closed mask (except empty)
    if (node.contentLength >= 2) {
      maskContent(buffer, node, collector, intents, packetIndex, 'ldap-octet-mask')
    }
    return
  }
  for (const c of node.children) {
    // Preserve integers / enums / booleans
    if (
      !c.tag.constructed
      && (c.tag.number === ASN1_INTEGER || c.tag.number === ASN1_ENUMERATED || c.tag.number === ASN1_BOOLEAN)
    ) {
      continue
    }
    walkSensitive(buffer, c, collector, mapping, intents, packetIndex, issues)
  }
}

function sanitizeDnOrText(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (!isOctet(node) || node.contentLength === 0) return
  const abs = node.contentOffset
  const len = node.contentLength
  const original = latin1(buffer, abs, len)
  if (!looksLikeDn(original)) {
    // bare username in bind name
    mapOctetCategory(buffer, node, 'user-id', collector, mapping, intents, packetIndex)
    return
  }
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    const liveDn = rewriteDn(original, (cat, val) => {
      const canon = canonicalizeIdentity(cat, val)
      if (!canon) return 'x'.repeat(val.length)
      try {
        return live.aliasFor(cat, canon, { kind: 'text-ascii', byteLength: val.length }, val)
      } catch {
        return live.map(cat, canon).slice(0, val.length).padEnd(val.length, 'x')
      }
    })
    return computeFixedLengthAsciiBytes(abs, len, liveDn)
  }, { fallbackKind: 'text-x', protocol: 'ldap', category: 'person', packetIndex })
  // Discovery: register primary CN/UID for alias consistency across LDAP/Kerberos/NTLM.
  for (const rdn of splitDn(original)) {
    const eq = rdn.indexOf('=')
    if (eq <= 0) continue
    const t = rdn.slice(0, eq).toUpperCase()
    const value = rdn.slice(eq + 1)
    const cat: IdentityCategory | null =
      t === 'CN' || t === 'GIVENNAME' || t === 'SN'
        ? 'person'
        : t === 'UID' || t === 'SAMACCOUNTNAME'
          ? 'user-id'
          : t === 'DC'
            ? 'hostname'
            : null
    if (!cat) continue
    const canon = canonicalizeIdentity(cat, value)
    if (canon) intents?.recordEntityReplacement(packetIndex, abs, cat, canon, len)
  }
  void mapping
}

function rewriteDn(
  dn: string,
  mapValue?: (cat: IdentityCategory, value: string) => string,
): string {
  const rdns = splitDn(dn)
  const out: string[] = []
  for (const rdn of rdns) {
    const eq = rdn.indexOf('=')
    if (eq <= 0) {
      out.push(rdn)
      continue
    }
    const type = rdn.slice(0, eq)
    const value = rdn.slice(eq + 1)
    const t = type.toUpperCase()
    let cat: IdentityCategory | null = null
    if (t === 'CN' || t === 'GIVENNAME' || t === 'SN') cat = 'person'
    else if (t === 'UID' || t === 'SAMACCOUNTNAME') cat = 'user-id'
    else if (t === 'DC') cat = 'hostname'
    else if (t === 'OU') cat = null // mask
    if (cat && mapValue) {
      out.push(`${type}=${mapValue(cat, value)}`)
    } else if (cat) {
      // placeholder length-preserving for deferred path first pass
      out.push(`${type}=${'x'.repeat(value.length)}`)
    } else {
      out.push(`${type}=${'x'.repeat(value.length)}`)
    }
  }
  return out.join(',')
}

function splitDn(dn: string): string[] {
  const parts: string[] = []
  let cur = ''
  for (let i = 0; i < dn.length; i++) {
    const ch = dn[i]!
    if (ch === '\\' && i + 1 < dn.length) {
      cur += ch + dn[i + 1]!
      i++
      continue
    }
    if (ch === ',') {
      parts.push(cur)
      cur = ''
      continue
    }
    cur += ch
  }
  if (cur.length > 0 || parts.length > 0) parts.push(cur)
  return parts
}

function looksLikeDn(text: string): boolean {
  if (text.length < 3 || !text.includes('=')) return false
  return /(?:^|,)\s*(?:CN|OU|DC|UID|O|L|ST|C|SAMACCOUNTNAME)=/i.test(text)
}

function mapOctetCategory(
  buffer: Uint8Array,
  node: BerNode,
  category: IdentityCategory,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  if (node.contentLength <= 0) return
  const abs = node.contentOffset
  const len = node.contentLength
  const text = latin1(buffer, abs, len)
  const canon = canonicalizeIdentity(category, text)
  if (!canon) {
    mask(collector, intents, packetIndex, abs, len, `ldap-${category}-bad`)
    return
  }
  const constraint = { kind: 'text-ascii' as const, byteLength: len }
  intents?.recordEntityReplacement(packetIndex, abs, category, canon, len, constraint, text)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    try {
      const alias = live.aliasFor(category, canon, constraint, text)
      return computeFixedLengthAsciiBytes(abs, len, alias)
    } catch {
      return createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain: `ldap-${category}` })
    }
  }, deferredTextMapMeta('ldap', packetIndex, category, text, len, { canonical: canon }))
  void mapping
}

function mapOpaqueBinary(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  mapping: MappingLike,
  intents: IntentCollector | undefined,
  packetIndex: number,
): void {
  const abs = node.contentOffset
  const len = node.contentLength
  if (len <= 0) return
  let hex = ''
  for (let i = 0; i < len; i++) hex += buffer[abs + i]!.toString(16).padStart(2, '0')
  const canon = `ldap-bin/${hex.slice(0, 32)}`
  intents?.recordEntityReplacement(packetIndex, abs, 'opaque-id', canon, len)
  collector.addDeferred(abs, len, ({ mapping: live }) => {
    const alias = live.map('opaque-id', canon)
    return createProtocolNeutralMaskFill({
      length: len,
      packetIndex,
      offset: abs,
      domain: `ldap-bin:${alias}`,
    })
  }, { fallbackKind: 'binary-mask', protocol: 'ldap', category: 'opaque-id', packetIndex })
  void mapping
}

function firstSequence(op: BerNode): BerNode | null {
  // APPLICATION / CONTEXT constructed ops expose SEQUENCE fields as direct children
  return op.tag.constructed ? op : null
}

function isOctet(node: BerNode): boolean {
  return !node.tag.constructed && node.tag.number === ASN1_OCTET_STRING
}

function maskContent(
  buffer: Uint8Array,
  node: BerNode,
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  domain: string,
): void {
  if (node.contentLength <= 0) return
  mask(collector, intents, packetIndex, node.contentOffset, node.contentLength, domain)
  void buffer
}

function mask(
  collector: PatchCollector,
  intents: IntentCollector | undefined,
  packetIndex: number,
  abs: number,
  len: number,
  domain: string,
): void {
  collector.maskRange(abs, createProtocolNeutralMaskFill({ length: len, packetIndex, offset: abs, domain }))
  intents?.recordMaskRange(packetIndex, abs, len, domain, 'ldap')
}

function latin1(buffer: Uint8Array, abs: number, len: number): string {
  return new TextDecoder('latin1').decode(buffer.subarray(abs, abs + len))
}

void ASN1_SEQUENCE
void ASN1_SET
