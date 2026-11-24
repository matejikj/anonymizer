/**
 * `application/vnd.*.radioprotocol` SIP body — previously fell entirely into the
 * generic "unsupported content-type" full-body redaction.
 * Now parsed structurally: identity fields (User, SubscriptionId, UserLocation, MessageId)
 * are pseudonymized, protocol/diagnostic fields (MessageContentType, ServiceType,
 * ProtocolVersion, MessageType, Expire, GroupType) pass through unchanged, and anything
 * unrecognized (e.g. GroupName) is safely redacted rather than guessed at.
 */

import { describe, expect, it } from 'vitest';
import {
  buildRadioProtocolBodyPlan,
  looksLikeRadioProtocolBody,
  parseRadioProtocolBody,
} from '../../../src/pcap/protocols/application/sip/radioProtocolBody';
import { sanitizeSip } from '../../../src/pcap/sanitize/sip';
import { PatchCollector } from '../../../src/pcap/sanitize/PatchCollector';
import { SessionMapping } from '../../../src/pcap/anonymization/mapping';

function latin1(text: string): Uint8Array {
  return new Uint8Array(Array.from(text, (c) => c.charCodeAt(0) & 0xff));
}

function buildSipMessage(headers: string[], bodyLines: string[]): Uint8Array {
  const body = bodyLines.join('\n');
  const allHeaders = [...headers, `Content-Length: ${body.length}`];
  const text = `${allHeaders.join('\r\n')}\r\n\r\n${body}`;
  return latin1(text);
}

function applyPatches(buf: Uint8Array, collector: PatchCollector): string {
  const output = new Uint8Array(buf);
  for (const patch of collector.getPatches()) output.set(patch.data, patch.offset);
  return new TextDecoder('latin1').decode(output);
}

// Synthetic body shapes: Subscription, minimal Subscription, and GroupChange.
const SUBSCRIPTION_BODY = [
  'MessageContentType: Subscription',
  'MessageContent: {Expire: 60, User: DISP UNIT15, SubscriptionId: 19679069611771353456366u15,',
  '  UserLocation: testLocation}',
  'ServiceType: TextMessaging',
  'ProtocolVersion: RadioProtocol-1.8.0',
  'MessageType: Request',
  'MessageId: d52b2668-616b-4763-9991-daea150d089d',
];

const MINIMAL_SUBSCRIPTION_BODY = [
  'MessageContentType: Subscription',
  'MessageContent: {Expire: 60}',
  'ServiceType: TextMessaging',
  'ProtocolVersion: RadioProtocol-1.8.0',
  'MessageType: Response',
  'MessageId: d52b2668-616b-4763-9991-daea150d089d',
];

const GROUP_CHANGE_BODY = [
  'MessageContentType: GroupChange',
  "MessageContent: {GroupName: '1001', GroupType: STATIC}",
  'ServiceType: Calling',
  'ProtocolVersion: RadioProtocol-1.8.0',
  'MessageType: Request',
  'MessageId: ccb1a37a-8f06-4c0f-a9d4-c326483d09d5',
];

describe('looksLikeRadioProtocolBody', () => {
  it('matches the exact content-type case-insensitively', () => {
    expect(looksLikeRadioProtocolBody('application/vnd.example.radioprotocol')).toBe(true);
    expect(looksLikeRadioProtocolBody('Application/Vnd.Example.RadioProtocol')).toBe(true);
    expect(looksLikeRadioProtocolBody('application/sdp')).toBe(false);
    expect(looksLikeRadioProtocolBody(null)).toBe(false);
  });
});

describe('parseRadioProtocolBody', () => {
  it('parses a Subscription body with a multi-line MessageContent map', () => {
    const body = SUBSCRIPTION_BODY.join('\n');
    const buf = latin1(body);
    const result = parseRadioProtocolBody(buf, { offset: 0, length: buf.length });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const topKeys = result.body.topFields.map((f) => f.key);
    expect(topKeys).toEqual(['MessageContentType', 'ServiceType', 'ProtocolVersion', 'MessageType', 'MessageId']);
    expect(result.body.contentFields).not.toBeNull();
    const contentKeys = result.body.contentFields!.map((f) => f.key);
    expect(contentKeys).toEqual(['Expire', 'User', 'SubscriptionId', 'UserLocation']);
    const userField = result.body.contentFields!.find((f) => f.key === 'User')!;
    expect(latin1ToString(buf, userField.valueSpan)).toBe('DISP UNIT15');
    const locationField = result.body.contentFields!.find((f) => f.key === 'UserLocation')!;
    expect(latin1ToString(buf, locationField.valueSpan)).toBe('testLocation');
  });

  it('parses a GroupChange body with a single-quoted value', () => {
    const body = GROUP_CHANGE_BODY.join('\n');
    const buf = latin1(body);
    const result = parseRadioProtocolBody(buf, { offset: 0, length: buf.length });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const groupName = result.body.contentFields!.find((f) => f.key === 'GroupName')!;
    expect(latin1ToString(buf, groupName.valueSpan)).toBe('1001');
    const groupType = result.body.contentFields!.find((f) => f.key === 'GroupType')!;
    expect(latin1ToString(buf, groupType.valueSpan)).toBe('STATIC');
  });

  it('fails closed on unbalanced MessageContent braces', () => {
    const buf = latin1('MessageContentType: Subscription\nMessageContent: {Expire: 60\nServiceType: Calling\n');
    const result = parseRadioProtocolBody(buf, { offset: 0, length: buf.length });
    expect(result.ok).toBe(false);
  });

  it('fails closed on a structurally unfamiliar line', () => {
    const buf = latin1('not a key value line at all\n');
    const result = parseRadioProtocolBody(buf, { offset: 0, length: buf.length });
    expect(result.ok).toBe(false);
  });
});

function latin1ToString(buf: Uint8Array, span: { offset: number; length: number }): string {
  return new TextDecoder('latin1').decode(buf.slice(span.offset, span.offset + span.length));
}

describe('buildRadioProtocolBodyPlan classification', () => {
  it('maps identity fields, preserves diagnostic fields, redacts unknown fields', () => {
    const body = GROUP_CHANGE_BODY.join('\n');
    const buf = latin1(body);
    const plan = buildRadioProtocolBodyPlan(buf, { offset: 0, length: buf.length });
    expect(plan.ok).toBe(true);
    if (!plan.ok) return;
    // GroupName (unknown, quoted) -> redact; GroupType (known-benign) -> no operation at all.
    const redacted = plan.operations.filter((o) => o.action === 'redact');
    expect(redacted.length).toBe(1);
    expect(latin1ToString(buf, redacted[0]!.span)).toBe('1001');
  });
});

describe('sanitizeSip integration — radio protocol body', () => {
  it('pseudonymizes identity fields but preserves protocol/diagnostic fields (Subscription)', () => {
    const buf = buildSipMessage(
      [
        'MESSAGE sip:RADIO2@10.230.0.20:5060 SIP/2.0',
        'Via: SIP/2.0/UDP 10.230.0.10:5060;branch=z9hG4bK1',
        'From: "DISP UNIT15" <sip:DISPUNIT15@10.230.0.10>;tag=t1',
        'To: <sip:RADIO2@10.230.0.20>',
        'Call-ID: c1@10.230.0.10',
        'CSeq: 1 MESSAGE',
        'Content-Type: application/vnd.example.radioprotocol',
      ],
      SUBSCRIPTION_BODY,
    );
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    expect(sanitizeSip(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector);

    // identities gone
    expect(out).not.toContain('DISP UNIT15');
    expect(out).not.toContain('19679069611771353456366u15');
    expect(out).not.toContain('testLocation');
    expect(out).not.toContain('d52b2668-616b-4763-9991-daea150d089d');
    // protocol/diagnostic fields preserved
    expect(out).toContain('MessageContentType: Subscription');
    expect(out).toContain('ServiceType: TextMessaging');
    expect(out).toContain('ProtocolVersion: RadioProtocol-1.8.0');
    expect(out).toContain('MessageType: Request');
    expect(out).toContain('Expire: 60');
    // structure survives
    expect(out).toMatch(/MessageContent: \{Expire: 60, User: .+, SubscriptionId: .+,\n {2}UserLocation: .+\}/);
  });

  it('redacts GroupName but preserves GroupType/MessageContentType (GroupChange)', () => {
    const buf = buildSipMessage(
      [
        'MESSAGE sip:RADIO2@10.230.0.20:5060 SIP/2.0',
        'Via: SIP/2.0/UDP 10.230.0.10:5060;branch=z9hG4bK2',
        'From: "DISP UNIT15" <sip:DISPUNIT15@10.230.0.10>;tag=t2',
        'To: <sip:RADIO2@10.230.0.20>',
        'Call-ID: c2@10.230.0.10',
        'CSeq: 2 MESSAGE',
        'Content-Type: application/vnd.example.radioprotocol',
      ],
      GROUP_CHANGE_BODY,
    );
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    expect(sanitizeSip(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector);

    expect(out).not.toContain("'1001'");
    expect(out).toContain('GroupType: STATIC');
    expect(out).toContain('MessageContentType: GroupChange');
  });

  it('falls back to full-body redaction when the structure is unfamiliar (fail-closed)', () => {
    const buf = buildSipMessage(
      [
        'MESSAGE sip:RADIO2@10.230.0.20:5060 SIP/2.0',
        'Via: SIP/2.0/UDP 10.230.0.10:5060;branch=z9hG4bK3',
        'From: "DISP UNIT15" <sip:DISPUNIT15@10.230.0.10>;tag=t3',
        'To: <sip:RADIO2@10.230.0.20>',
        'Call-ID: c3@10.230.0.10',
        'CSeq: 3 MESSAGE',
        'Content-Type: application/vnd.example.radioprotocol',
      ],
      ['this is not a well-formed radioprotocol body at all'],
    );
    const collector = new PatchCollector(buf.length);
    const mapping = new SessionMapping();
    expect(sanitizeSip(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector);
    expect(out).not.toContain('this is not a well-formed radioprotocol body at all');
  });

  it('is consistent with the SIP display-name alias for the same "User" value', () => {
    const buf = buildSipMessage(
      [
        'MESSAGE sip:RADIO2@10.230.0.20:5060 SIP/2.0',
        'Via: SIP/2.0/UDP 10.230.0.10:5060;branch=z9hG4bK4',
        'From: "DISP UNIT15" <sip:DISPUNIT15@10.230.0.10>;tag=t4',
        'To: <sip:RADIO2@10.230.0.20>',
        'Call-ID: c4@10.230.0.10',
        'CSeq: 4 MESSAGE',
        'Content-Type: application/vnd.example.radioprotocol',
      ],
      MINIMAL_SUBSCRIPTION_BODY.map((l) => (l.startsWith('MessageContent:') ? 'MessageContent: {Expire: 60, User: DISP UNIT15}' : l)),
    );
    const mapping = new SessionMapping();
    const collector = new PatchCollector(buf.length);
    expect(sanitizeSip(buf, 0, buf.length, collector, mapping)).toBe(true);
    const out = applyPatches(buf, collector);

    // Both the From display-name and the body's User field use category 'sip-user' with the
    // same canonical text "DISP UNIT15" — they must resolve to the identical alias.
    const fromMatch = /From: "([^"]+)"/.exec(out);
    const userMatch = /User: ([^}]+)}/.exec(out.split('MessageContent:')[1] ?? '');
    expect(fromMatch).toBeTruthy();
    expect(userMatch).toBeTruthy();
    expect(fromMatch![1]).toBe(userMatch![1]);
  });
});
