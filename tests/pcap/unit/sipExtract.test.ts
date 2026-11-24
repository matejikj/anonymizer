import { describe, expect, it } from 'vitest';
import {
  applySipRedactionPlan,
  buildSipRedactionPlan,
  decodeLatin1Span,
  delimitersPreserved,
  extractSipEntities,
  isCredentialEntity,
  parseSipMessage,
  type SipSensitiveEntity,
  type ByteSpan,
} from '../../../src/pcap/protocols/application/sip';

function latin1(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function parseComplete(buf: Uint8Array) {
  const result = parseSipMessage(buf);
  expect(result.kind).toBe('complete');
  if (result.kind !== 'complete') throw new Error('expected complete parse');
  return result.message;
}

function spanText(buf: Uint8Array, span: ByteSpan): string {
  return decodeLatin1Span(buf, span);
}

function entitiesForHeader(entities: readonly SipSensitiveEntity[], header: string) {
  return entities.filter((e) => e.headerCanonicalName === header);
}

function expectNoMapCredentials(entities: readonly SipSensitiveEntity[]): void {
  for (const e of entities) {
    if (isCredentialEntity(e)) {
      expect(e.action).toBe('redact');
      expect(e.mappingCategory).toBeNull();
      expect(e.canonicalText).toBe('');
    }
  }
}

describe('SIP identity extraction (step 4)', () => {
  describe('Request-URI', () => {
    it('extracts user, host, and port from a positive INVITE', () => {
      const buf = latin1('INVITE sip:alice@example.com:5060;transport=udp SIP/2.0\r\nContent-Length: 0\r\n\r\n');
      const message = parseComplete(buf);
      const { entities } = extractSipEntities(message, buf);

      expect(entities.some((e) => e.kind === 'sip-user' && e.headerCanonicalName === 'request-uri')).toBe(true);
      expect(entities.some((e) => e.kind === 'host' && spanText(buf, e.span) === 'example.com')).toBe(true);
      expect(entities.some((e) => e.kind === 'port' && spanText(buf, e.span) === '5060')).toBe(true);
    });

    it('does not invent a user when the URI has no user part (negative)', () => {
      const buf = latin1('INVITE sip:192.0.2.10:5060 SIP/2.0\r\nContent-Length: 0\r\n\r\n');
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      expect(entities.filter((e) => e.kind === 'sip-user' && e.headerCanonicalName === 'request-uri')).toHaveLength(0);
      expect(entities.some((e) => e.kind === 'ipv4' && spanText(buf, e.span) === '192.0.2.10')).toBe(true);
    });

    it('extracts tel URI phone numbers as sip-phone mapping category', () => {
      const buf = latin1('INVITE tel:+420777123456 SIP/2.0\r\nContent-Length: 0\r\n\r\n');
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      const phone = entities.find((e) => e.kind === 'tel-phone');
      expect(phone?.mappingCategory).toBe('sip-phone');
      expect(spanText(buf, phone!.span)).toBe('+420777123456');
      expect(entities.some((e) => e.kind === 'host')).toBe(false);
    });

    it('T45 — sip:+user and user=phone map as sip-phone; bare digits stay sip-user', () => {
      const plusBuf = latin1(
        'INVITE sip:+420777123456@carrier.example SIP/2.0\r\nContent-Length: 0\r\n\r\n',
      );
      const { entities: plusEntities } = extractSipEntities(parseComplete(plusBuf), plusBuf);
      const plusUser = plusEntities.find((e) => e.canonicalText === '+420777123456');
      expect(plusUser?.mappingCategory).toBe('sip-phone');

      const paramBuf = latin1(
        'INVITE sip:777123456@carrier.example;user=phone SIP/2.0\r\nContent-Length: 0\r\n\r\n',
      );
      const { entities: paramEntities } = extractSipEntities(parseComplete(paramBuf), paramBuf);
      const paramUser = paramEntities.find((e) => e.canonicalText === '777123456');
      expect(paramUser?.mappingCategory).toBe('sip-phone');

      const bareBuf = latin1(
        'INVITE sip:1234@pbx.example SIP/2.0\r\nContent-Length: 0\r\n\r\n',
      );
      const { entities: bareEntities } = extractSipEntities(parseComplete(bareBuf), bareBuf);
      const bareUser = bareEntities.find((e) => e.canonicalText === '1234');
      expect(bareUser?.mappingCategory).toBe('sip-user');
    });
  });

  describe('From', () => {
    it('extracts display name, URI parts, and tag (positive)', () => {
      const buf = latin1([
        'INVITE sip:b@c SIP/2.0\r\n',
        'From: "Alice Example" <sip:alice@corp.example>;tag=abc123\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);

      expect(entities.some((e) => e.kind === 'display-name' && e.canonicalText === 'Alice Example')).toBe(true);
      expect(entities.some((e) => e.kind === 'sip-user' && spanText(buf, e.span) === 'alice')).toBe(true);
      expect(entities.some((e) => e.kind === 'sip-token' && e.parameterName === 'tag')).toBe(true);
    });

    it('ignores structural headers (negative)', () => {
      const buf = latin1('INVITE sip:a@b SIP/2.0\r\nFrom: <sip:a@b>\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n');
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      expect(entities.some((e) => e.headerCanonicalName === 'cseq')).toBe(false);
    });

    it('redacts malformed name-addr header value fail-closed', () => {
      const secret = 'unclosed-secret-user';
      const buf = latin1(`INVITE sip:a@b SIP/2.0\r\nFrom: "${secret}\r\nContent-Length: 0\r\n\r\n`);
      const { entities, issues } = extractSipEntities(parseComplete(buf), buf);
      expect(issues.some((i) => i.startsWith('malformed-name-addr:'))).toBe(true);
      expect(entities.some((e) => e.headerCanonicalName === 'from' && e.action === 'redact')).toBe(true);
      const plan = buildSipRedactionPlan(entities);
      const out = new TextDecoder('latin1').decode(applySipRedactionPlan(buf, plan));
      expect(out).not.toContain(secret);
    });
  });

  describe('To', () => {
    it('extracts URI identity (positive)', () => {
      const buf = latin1('INVITE sip:a@b SIP/2.0\r\nTo: <sip:bob@example.com>\r\nContent-Length: 0\r\n\r\n');
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      expect(entities.some((e) => e.headerCanonicalName === 'to' && e.kind === 'sip-user')).toBe(true);
    });
  });

  describe('Contact', () => {
    it('extracts multiple comma-separated contacts (positive)', () => {
      const buf = latin1([
        'REGISTER sip:r SIP/2.0\r\n',
        'Contact: <sip:a@1.example>, <sip:b@2.example>\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      const users = entities.filter((e) => e.headerCanonicalName === 'contact' && e.kind === 'sip-user');
      expect(users.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Via', () => {
    it('extracts sent-by host, port, and branch (positive)', () => {
      const buf = latin1([
        'INVITE sip:a@b SIP/2.0\r\n',
        'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      expect(entities.some((e) => e.headerCanonicalName === 'via' && e.kind === 'ipv4')).toBe(true);
      expect(entities.some((e) => e.headerCanonicalName === 'via' && e.kind === 'port')).toBe(true);
      expect(entities.some((e) => e.parameterName === 'branch' && e.kind === 'sip-token')).toBe(true);
    });

    it('does not extract From identities from Via (negative)', () => {
      const buf = latin1('INVITE sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060\r\nContent-Length: 0\r\n\r\n');
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      expect(entities.some((e) => e.headerCanonicalName === 'from')).toBe(false);
    });

    it('records malformed Via (malformed)', () => {
      const buf = latin1('INVITE sip:a@b SIP/2.0\r\nVia: not-a-via\r\nContent-Length: 0\r\n\r\n');
      const { issues } = extractSipEntities(parseComplete(buf), buf);
      expect(issues).toContain('malformed-via');
    });
  });

  describe('Call-ID', () => {
    it('maps Call-ID as a correlation token (positive)', () => {
      const buf = latin1('INVITE sip:a@b SIP/2.0\r\nCall-ID: sess-42@host.example\r\nContent-Length: 0\r\n\r\n');
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      const callId = entities.find((e) => e.kind === 'call-id')!;
      expect(callId.action).toBe('map');
      expect(callId.mappingCategory).toBe('sip-call-id');
      expect(callId.canonicalText).toBe('sess-42@host.example');
    });
  });

  describe('Route / Record-Route / Reply-To', () => {
    it('extracts URI parts from routing headers (positive)', () => {
      const buf = latin1([
        'INVITE sip:a@b SIP/2.0\r\n',
        'Route: <sip:proxy@edge.example>\r\n',
        'Record-Route: <sip:rr@middle.example>\r\n',
        'Reply-To: <sip:desk@support.example>\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      for (const header of ['route', 'record-route', 'reply-to']) {
        expect(entitiesForHeader(entities, header).some((e) => e.kind === 'host')).toBe(true);
      }
    });
  });

  describe('Refer-To / Referred-By / P-Asserted-Identity / Remote-Party-ID / Diversion / History-Info', () => {
    it('extracts identity URIs from extension headers (positive)', () => {
      const buf = latin1([
        'REFER sip:a@b SIP/2.0\r\n',
        'Refer-To: <sip:target@example.com>\r\n',
        'Referred-By: <sip:agent@example.com>\r\n',
        'P-Asserted-Identity: <sip:+420777123456@carrier.example>\r\n',
        'P-Preferred-Identity: <sip:user@example.com>\r\n',
        'Remote-Party-ID: <sip:party@example.com>;party=calling\r\n',
        'Diversion: <sip:div@example.com>;reason=unconditional\r\n',
        'History-Info: <sip:hist@example.com>;index=1\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      for (const header of [
        'refer-to',
        'referred-by',
        'p-asserted-identity',
        'p-preferred-identity',
        'remote-party-id',
        'diversion',
        'history-info',
      ]) {
        expect(entitiesForHeader(entities, header).length).toBeGreaterThan(0);
      }
    });
  });

  describe('Authorization / Proxy-Authorization / WWW-Authenticate', () => {
    it('redacts credential parameters without mapping (positive)', () => {
      const buf = latin1([
        'REGISTER sip:r SIP/2.0\r\n',
        'Authorization: Digest username="alice", realm="corp.example", nonce="deadbeef", uri="sip:corp.example", response="abc123"\r\n',
        'Proxy-Authorization: Digest username="bob", response="zzz"\r\n',
        'WWW-Authenticate: Digest realm="corp.example", nonce="cafebabe", opaque="secret"\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      const creds = entities.filter(isCredentialEntity);
      expect(creds.length).toBeGreaterThan(0);
      expectNoMapCredentials(creds);
      expect(creds.some((e) => e.parameterName === 'response')).toBe(true);
      expect(creds.some((e) => e.parameterName === 'nonce')).toBe(true);
    });

    it('redacts unknown credential parameters (deny-by-default)', () => {
      const buf = latin1([
        'REGISTER sip:r SIP/2.0\r\n',
        'Authorization: Digest foo="UnknownSecret42"\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      const creds = entities.filter(isCredentialEntity);
      expect(creds.some((e) => e.parameterName === 'foo')).toBe(true);
      const plan = buildSipRedactionPlan(entities);
      const redacted = applySipRedactionPlan(buf, plan);
      const text = new TextDecoder('latin1').decode(redacted);
      expect(text).not.toContain('UnknownSecret42');
    });

    it('extracts unquoted display name', () => {
      const buf = latin1([
        'INVITE sip:b@c SIP/2.0\r\n',
        'From: Alice Smith <sip:alice@corp.example>;tag=abc123\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      expect(entities.some((e) => e.kind === 'display-name' && e.canonicalText === 'Alice Smith')).toBe(true);
    });

    it('does not treat CSeq as credential (negative)', () => {
      const buf = latin1('INVITE sip:a@b SIP/2.0\r\nCSeq: 9 INVITE\r\nContent-Length: 0\r\n\r\n');
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      expect(entities.filter(isCredentialEntity)).toHaveLength(0);
    });

    it('redacts entire value when Digest params cannot be parsed (malformed)', () => {
      const buf = latin1('REGISTER sip:r SIP/2.0\r\nAuthorization: Digest broken\r\nContent-Length: 0\r\n\r\n');
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      const cred = entities.find((e) => e.headerCanonicalName === 'authorization')!;
      expect(cred.action).toBe('redact');
      expect(cred.kind).toBe('credential-value');
    });
  });

  describe('User-Agent / Server / Subject / unknown P-* / X-*', () => {
    it('redacts opaque product headers (positive)', () => {
      const buf = latin1([
        'INVITE sip:a@b SIP/2.0\r\n',
        'User-Agent: SecretPhone/1.2.3\r\n',
        'Server: SecretPBX/9.9\r\n',
        'Subject: Confidential topic\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      for (const header of ['user-agent', 'server', 'subject']) {
        const e = entities.find((x) => x.headerCanonicalName === header)!;
        expect(e.action).toBe('redact');
        expect(e.kind).toBe('opaque-text');
      }
    });

    it('redacts unknown vendor headers (positive)', () => {
      const buf = latin1([
        'INVITE sip:a@b SIP/2.0\r\n',
        'P-Charging-Vector: icid-value=secret\r\n',
        'X-Internal-Trace: node-17\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      expect(entities.filter((e) => e.kind === 'opaque-text')).toHaveLength(2);
    });

    it('does not redact Content-Length (negative)', () => {
      const buf = latin1('INVITE sip:a@b SIP/2.0\r\nContent-Length: 0\r\n\r\n');
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      expect(entities.some((e) => e.headerCanonicalName === 'content-length')).toBe(false);
    });
  });

  describe('Redaction plan', () => {
    it('preserves delimiters outside entity spans', () => {
      const buf = latin1([
        'INVITE sip:alice@example.com SIP/2.0\r\n',
        'From: "Alice" <sip:alice@example.com>;tag=abc\r\n',
        'Authorization: Digest username="alice", response="secret"\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const message = parseComplete(buf);
      const { entities } = extractSipEntities(message, buf);
      const plan = buildSipRedactionPlan(entities);
      const redacted = applySipRedactionPlan(buf, plan, (cat, canonical, len) => 'x'.repeat(Math.min(len, canonical.length)).padEnd(len, '-'));

      expect(delimitersPreserved(buf, redacted, message.span, entities.map((e) => e.span))).toBe(true);
    });

    it('masks credentials so they are not correlatable', () => {
      const buf = latin1([
        'REGISTER sip:r SIP/2.0\r\n',
        'Authorization: Digest username="alice", response="supersecret"\r\n',
        'Content-Length: 0\r\n\r\n',
      ].join(''));
      const { entities } = extractSipEntities(parseComplete(buf), buf);
      const plan = buildSipRedactionPlan(entities);
      const redacted = applySipRedactionPlan(buf, plan);
      const text = new TextDecoder('latin1').decode(redacted);
      expect(text).not.toContain('supersecret');
      expect(text).not.toContain('alice');
      expect(plan.operations.filter((o) => o.action === 'map' && o.canonicalText.includes('secret'))).toHaveLength(0);
    });
  });
});
