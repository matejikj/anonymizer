/**
 * Extract typed sensitive entities from a parsed SIP message (step 4 visitor).
 */

import type { SipEntityAction, SipExtractionResult, SipMappingCategory, SipSensitiveEntity } from './entities';
import type { SipParseLimits } from './limits';
import { DEFAULT_SIP_PARSE_LIMITS } from './limits';
import type { SipHeader, SipMessage, SipParameter, SipUri } from './types';
import { decodeLatin1Span, decodeUtf8Span } from './bytes';
import { CORRELATION_PARAMETERS, dispositionForHeader } from './headerPolicy';
import { entityKindForHost, hostMappingCategory } from './hostKind';
import {
  parseAuthParams,
  parseNameAddr,
  parseUriInSpan,
  parseViaSentBy,
  splitCommaSeparatedSpans,
} from './valueParts';

export interface ExtractSipEntitiesOptions {
  readonly limits?: SipParseLimits;
}

export function extractSipEntities(
  message: SipMessage,
  buffer: Uint8Array,
  options: ExtractSipEntitiesOptions = {},
): SipExtractionResult {
  const limits = options.limits ?? DEFAULT_SIP_PARSE_LIMITS;
  const entities: SipSensitiveEntity[] = [];
  const issues: string[] = [];

  if (message.startLine.kind === 'request') {
    extractUriParts(
      entities,
      buffer,
      message.startLine.requestUri,
      'request-uri',
      limits,
      issues,
    );
  }

  for (const header of message.headers) {
    extractHeaderEntities(entities, buffer, header, limits, issues);
  }

  return { entities, issues };
}

function extractHeaderEntities(
  out: SipSensitiveEntity[],
  buffer: Uint8Array,
  header: SipHeader,
  limits: SipParseLimits,
  issues: string[],
): void {
  const disposition = dispositionForHeader(header.canonicalNameText);

  switch (disposition) {
    case 'identity':
      extractNameAddrIdentityHeader(out, buffer, header, limits, issues);
      break;
    case 'stir-identity':
      extractStirIdentityHeader(out, header, issues);
      break;
    case 'call-id':
      pushEntity(out, {
        kind: 'call-id',
        span: header.value,
        action: 'map',
        canonicalText: header.valueText.trim(),
        headerCanonicalName: header.canonicalNameText,
        parameterName: null,
        mappingCategory: 'sip-call-id',
      });
      break;
    case 'via':
      extractViaHeader(out, buffer, header, issues);
      break;
    case 'credential':
      extractCredentialHeader(out, buffer, header);
      break;
    case 'geolocation':
      extractGeolocationHeader(out, header);
      break;
    case 'opaque-redact':
    case 'vendor-redact':
      pushEntity(out, {
        kind: 'opaque-text',
        span: header.value,
        action: 'redact',
        canonicalText: '',
        headerCanonicalName: header.canonicalNameText,
        parameterName: null,
        mappingCategory: null,
      });
      break;
    case 'absolute-time': {
      const text = header.valueText.trim();
      // T14 — RFC1123 → capture-aligned rewrite; anything else fail-closed mask.
      if (/^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(text)) {
        pushEntity(out, {
          kind: 'opaque-text',
          span: header.value,
          action: 'map',
          canonicalText: text,
          headerCanonicalName: header.canonicalNameText,
          parameterName: null,
          mappingCategory: null,
        });
      } else {
        pushEntity(out, {
          kind: 'opaque-text',
          span: header.value,
          action: 'redact',
          canonicalText: '',
          headerCanonicalName: header.canonicalNameText,
          parameterName: null,
          mappingCategory: null,
        });
      }
      break;
    }
    case 'structural':
      break;
  }
}

/**
 * STIR/SHAKEN Identity (RFC 8224) — mask the entire PASSporT token.
 * Any rewrite invalidates the signature → cryptographic_integrity MODIFIED.
 */
function extractStirIdentityHeader(
  out: SipSensitiveEntity[],
  header: SipHeader,
  issues: string[],
): void {
  issues.push('crypto-integrity-modified:sip-identity');
  pushEntity(out, {
    kind: 'opaque-text',
    span: header.value,
    action: 'redact',
    canonicalText: '',
    headerCanonicalName: header.canonicalNameText,
    parameterName: null,
    mappingCategory: null,
  });
}

function extractNameAddrIdentityHeader(
  out: SipSensitiveEntity[],
  buffer: Uint8Array,
  header: SipHeader,
  limits: SipParseLimits,
  issues: string[],
): void {
  const parts = splitCommaSeparatedSpans(
    buffer,
    header.value.offset,
    header.value.offset + header.value.length,
  );

  if (parts.length === 0) {
    issues.push(`empty-identity-header:${header.canonicalNameText}`);
    pushEntity(out, {
      kind: 'opaque-text',
      span: header.value,
      action: 'redact',
      canonicalText: '',
      headerCanonicalName: header.canonicalNameText,
      parameterName: null,
      mappingCategory: null,
    });
    return;
  }

  let anyParsed = false;
  for (const part of parts) {
    const nameAddr = parseNameAddr(buffer, part.offset, part.offset + part.length);
    if (!nameAddr) {
      issues.push(`malformed-name-addr:${header.canonicalNameText}`);
      continue;
    }
    anyParsed = true;

    if (nameAddr.displayName) {
      pushEntity(out, {
        kind: 'display-name',
        span: nameAddr.displayName.span,
        action: 'map',
        canonicalText: nameAddr.displayName.text,
        headerCanonicalName: header.canonicalNameText,
        parameterName: null,
        mappingCategory: 'sip-user',
      });
    }

    const uriParsed = parseUriInSpan(buffer, nameAddr.uriSpan, limits);
    if (!uriParsed.ok) {
      issues.push(`malformed-uri:${header.canonicalNameText}:${uriParsed.reason}`);
      continue;
    }

    extractUriParts(out, buffer, uriParsed.uri, header.canonicalNameText, limits, issues);
  }

  if (!anyParsed) {
    // CF-01 fail-closed: malformed identity header value is fully redacted.
    pushEntity(out, {
      kind: 'opaque-text',
      span: header.value,
      action: 'redact',
      canonicalText: '',
      headerCanonicalName: header.canonicalNameText,
      parameterName: null,
      mappingCategory: null,
    });
    return;
  }

  for (const param of header.parameters) {
    extractParameter(out, buffer, param, header.canonicalNameText, 'header-parameter');
  }
}

function extractViaHeader(
  out: SipSensitiveEntity[],
  buffer: Uint8Array,
  header: SipHeader,
  issues: string[],
): void {
  const sentBy = parseViaSentBy(
    buffer,
    header.value.offset,
    header.value.offset + header.value.length,
  );
  if (!sentBy) {
    issues.push('malformed-via');
    return;
  }

  const hostText = decodeLatin1Span(buffer, sentBy.hostSpan);
  const hostCategory = hostMappingCategory(hostText);
  pushEntity(out, {
    kind: entityKindForHost(hostCategory),
    span: sentBy.hostSpan,
    action: 'map',
    canonicalText: hostText,
    headerCanonicalName: 'via',
    parameterName: null,
    mappingCategory: hostCategory,
  });

  if (sentBy.portSpan) {
    const portText = decodeLatin1Span(buffer, sentBy.portSpan);
    pushEntity(out, {
      kind: 'port',
      span: sentBy.portSpan,
      action: 'map',
      canonicalText: portText,
      headerCanonicalName: 'via',
      parameterName: 'port',
      mappingCategory: 'port',
    });
  }

  for (const param of header.parameters) {
    if (param.name && decodeLatin1Span(buffer, param.name).toLowerCase() === 'branch') {
      extractParameter(out, buffer, param, header.canonicalNameText, 'header-parameter');
    } else if (param.name) {
      const nameText = decodeLatin1Span(buffer, param.name).toLowerCase();
      if (nameText === 'received' || nameText === 'rport') {
        extractParameter(out, buffer, param, header.canonicalNameText, 'header-parameter');
      } else if (CORRELATION_PARAMETERS.has(nameText)) {
        extractParameter(out, buffer, param, header.canonicalNameText, 'header-parameter');
      }
    }
  }
}

function extractCredentialHeader(out: SipSensitiveEntity[], buffer: Uint8Array, header: SipHeader): void {
  const valueEnd = header.value.offset + header.value.length;
  const parsed = parseAuthParams(buffer, header.value.offset, valueEnd);

  if (parsed.params.length === 0) {
    pushEntity(out, {
      kind: 'credential-value',
      span: header.value,
      action: 'redact',
      canonicalText: '',
      headerCanonicalName: header.canonicalNameText,
      parameterName: null,
      mappingCategory: null,
    });
    return;
  }

  for (const param of parsed.params) {
    pushEntity(out, {
      kind: 'credential-value',
      span: param.valueSpan,
      action: 'redact',
      canonicalText: '',
      headerCanonicalName: header.canonicalNameText,
      parameterName: param.nameText,
      mappingCategory: null,
    });
  }

  if (!parsed.complete && parsed.tailOffset < valueEnd) {
    pushEntity(out, {
      kind: 'credential-value',
      span: { offset: parsed.tailOffset, length: valueEnd - parsed.tailOffset },
      action: 'redact',
      canonicalText: '',
      headerCanonicalName: header.canonicalNameText,
      parameterName: null,
      mappingCategory: null,
    });
  }
}

function extractUriParts(
  out: SipSensitiveEntity[],
  buffer: Uint8Array,
  uri: SipUri,
  headerName: string,
  _limits: SipParseLimits,
  _issues: string[],
): void {

  const scheme = decodeLatin1Span(buffer, uri.scheme).toLowerCase();

  if (scheme === 'tel') {
    const phoneText = decodeUtf8Span(buffer, uri.host);
    pushEntity(out, {
      kind: 'tel-phone',
      span: uri.host,
      action: 'map',
      canonicalText: phoneText,
      headerCanonicalName: headerName,
      parameterName: null,
      mappingCategory: 'sip-phone',
    });
    for (const param of uri.parameters) {
      extractParameter(out, buffer, param, headerName, 'uri-parameter');
    }
    return;
  }

  if (uri.user) {
    const userText = decodeUtf8Span(buffer, uri.user);
    // T45 — user=phone or international +user → sip-phone (cross-format phone);
    // bare digits without context stay sip-user (user principal, not phone).
    const phoneRole = scheme === 'tel'
      || userText.trim().startsWith('+')
      || uriHasUserPhoneParam(buffer, uri);
    pushEntity(out, {
      kind: phoneRole ? (scheme === 'tel' ? 'tel-phone' : 'sip-user') : 'sip-user',
      span: uri.user,
      action: 'map',
      canonicalText: userText,
      headerCanonicalName: headerName,
      parameterName: null,
      mappingCategory: phoneRole ? 'sip-phone' : 'sip-user',
    });
  }

  if (uri.password) {
    pushEntity(out, {
      kind: 'sip-password',
      span: uri.password,
      action: 'redact',
      canonicalText: '',
      headerCanonicalName: headerName,
      parameterName: 'password',
      mappingCategory: null,
    });
  }

  const hostText = decodeLatin1Span(buffer, uri.host);
  const hostCategory = hostMappingCategory(hostText);
  pushEntity(out, {
    kind: entityKindForHost(hostCategory),
    span: uri.host,
    action: 'map',
    canonicalText: hostText,
    headerCanonicalName: headerName,
    parameterName: null,
    mappingCategory: hostCategory,
  });

  if (uri.port) {
    const portText = decodeLatin1Span(buffer, uri.port);
    pushEntity(out, {
      kind: 'port',
      span: uri.port,
      action: 'map',
      canonicalText: portText,
      headerCanonicalName: headerName,
      parameterName: 'port',
      mappingCategory: 'port',
    });
  }

  for (const param of uri.parameters) {
    extractParameter(out, buffer, param, headerName, 'uri-parameter');
  }
}

/** RFC 3261 user=phone — proves the user part is a telephone subscriber. */
function uriHasUserPhoneParam(buffer: Uint8Array, uri: SipUri): boolean {
  for (const param of uri.parameters) {
    if (!param.name || !param.value) continue;
    const name = decodeLatin1Span(buffer, param.name).toLowerCase();
    if (name !== 'user') continue;
    const value = decodeUtf8Span(buffer, param.value).toLowerCase();
    if (value === 'phone') return true;
  }
  return false;
}

/**
 * T53 — Geolocation (RFC 6442): map `cid:` Content-ID refs; mask location-by-ref URIs.
 * Routing boolean tokens (yes/no) left untouched.
 */
function extractGeolocationHeader(out: SipSensitiveEntity[], header: SipHeader): void {
  const text = header.valueText
  const base = header.value.offset
  // cid:token (optional angle brackets / quotes)
  const cidRe = /\bcid:([^\s;>,]+)/gi
  let m: RegExpExecArray | null
  const covered: Array<{ start: number; end: number }> = []
  while ((m = cidRe.exec(text)) !== null) {
    const token = m[1]!.replace(/^<|>$/g, '')
    if (!token) continue
    const tokenInMatch = m[0]!.indexOf(token)
    const abs = base + m.index + tokenInMatch
    covered.push({ start: m.index, end: m.index + m[0]!.length })
    pushEntity(out, {
      kind: 'sip-token',
      span: { offset: abs, length: token.length },
      action: 'map',
      canonicalText: `sip-cid:${token}`,
      headerCanonicalName: header.canonicalNameText,
      parameterName: 'cid',
      mappingCategory: 'sip-token',
    })
  }
  // http(s) / sip location-by-reference URIs — full value redact (never fetch)
  const uriRe = /<?((?:https?|sips?):\/\/[^\s>;>]+)>?/gi
  while ((m = uriRe.exec(text)) !== null) {
    const uri = m[1]!
    const uriInMatch = m[0]!.indexOf(uri)
    const abs = base + m.index + uriInMatch
    covered.push({ start: m.index, end: m.index + m[0]!.length })
    pushEntity(out, {
      kind: 'opaque-text',
      span: { offset: abs, length: uri.length },
      action: 'redact',
      canonicalText: '',
      headerCanonicalName: header.canonicalNameText,
      parameterName: null,
      mappingCategory: null,
    })
  }
  // If header had neither cid nor URI (unexpected), fail-closed redact whole value
  if (covered.length === 0 && text.trim().length > 0) {
    // Preserve pure routing flags: "yes" / "no"
    if (/^(?:yes|no)$/i.test(text.trim())) return
    pushEntity(out, {
      kind: 'opaque-text',
      span: header.value,
      action: 'redact',
      canonicalText: '',
      headerCanonicalName: header.canonicalNameText,
      parameterName: null,
      mappingCategory: null,
    })
  }
}

function extractParameter(
  out: SipSensitiveEntity[],
  buffer: Uint8Array,
  param: SipParameter,
  headerName: string,
  kind: 'uri-parameter' | 'header-parameter',
): void {
  if (!param.value) return;

  const nameText = decodeLatin1Span(buffer, param.name).toLowerCase();
  const valueText = decodeUtf8Span(buffer, param.value);

  if (nameText === 'received') {
    const hostCategory = hostMappingCategory(valueText);
    pushEntity(out, {
      kind: entityKindForHost(hostCategory),
      span: param.value,
      action: 'map',
      canonicalText: valueText,
      headerCanonicalName: headerName,
      parameterName: nameText,
      mappingCategory: hostCategory,
    });
    return;
  }

  if (nameText === 'rport') {
    pushEntity(out, {
      kind: 'port',
      span: param.value,
      action: 'map',
      canonicalText: valueText,
      headerCanonicalName: headerName,
      parameterName: nameText,
      mappingCategory: 'port',
    });
    return;
  }

  if (CORRELATION_PARAMETERS.has(nameText) || nameText === 'tag') {
    pushEntity(out, {
      kind: 'sip-token',
      span: param.value,
      action: 'map',
      canonicalText: valueText,
      headerCanonicalName: headerName,
      parameterName: nameText,
      mappingCategory: 'sip-token',
    });
    return;
  }

  if (nameText === 'user' && valueText === 'phone') {
    return;
  }

  pushEntity(out, {
    kind,
    span: param.value,
    action: 'map',
    canonicalText: valueText,
    headerCanonicalName: headerName,
    parameterName: nameText,
    mappingCategory: 'sip-token',
  });
}

function pushEntity(out: SipSensitiveEntity[], entity: SipSensitiveEntity): void {
  out.push(entity);
}

export function entityActionRequiresMapping(action: SipEntityAction): boolean {
  return action === 'map';
}

export function isCredentialEntity(entity: SipSensitiveEntity): boolean {
  return entity.kind === 'credential-value' || entity.kind === 'sip-password';
}

export function mappingCategoryForEntity(entity: SipSensitiveEntity): SipMappingCategory | null {
  return entity.mappingCategory;
}
