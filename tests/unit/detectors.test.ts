import { describe, expect, it } from 'vitest'
import { buildLineIndex } from '../../src/engine/lineIndex.ts'
import {
  detectIps,
  detectHostnames,
  detectSipPhones,
  detectEmails,
  detectUserIds,
  detectContextualPersons,
  detectContextualIdentifiers,
  detectCustomRules,
  detectPorts,
} from '../../src/engine/detectors/index.ts'
import { DEFAULT_DETECTOR_CONFIG, type DetectorConfig } from '../../src/domain/types.ts'

function run(detect: typeof detectIps, text: string, config?: DetectorConfig) {
  return detect(text, buildLineIndex(text), config ?? DEFAULT_DETECTOR_CONFIG)
}

describe('builtin detectors', () => {
  it('detects valid IPv4 with token boundaries', () => {
    const text = 'peer 10.16.1.105 port; version 12.6.2; bad 999.1.1.1; time 10:16:01'
    const matches = run(detectIps, text)
    expect(matches.map((m) => m.original)).toEqual(['10.16.1.105'])
  })

  it('detects hostnames with configured suffixes', () => {
    const text = 'ws desk-ws07-brn.corp.example sip ldap-pra.corp.example'
    const matches = run(detectHostnames, text)
    expect(matches.map((m) => m.normalized).sort()).toEqual([
      'desk-ws07-brn.corp.example',
      'ldap-pra.corp.example',
    ])
  })

  it('detects numeric SIP user parts only', () => {
    const text = 'sip:972051127@10.37.63.169 sip:disp5@10.16.1.105 tel:+420123456789'
    const matches = run(detectSipPhones, text)
    expect(matches.map((m) => m.original).sort()).toEqual(['+420123456789', '972051127'])
  })

  it('detects emails and skips sip-user@ip', () => {
    const text = 'mail ops@example.com and sip:ops@10.1.1.1'
    const matches = run(detectEmails, text)
    expect(matches.map((m) => m.original)).toEqual(['ops@example.com'])
  })

  it('detects dispN user ids', () => {
    const text = "User 'disp4' and disp22 logged; display not matched"
    const matches = run(detectUserIds, text)
    expect(matches.map((m) => m.normalized).sort()).toEqual(['disp22', 'disp4'])
  })

  it('detects contextual persons', () => {
    const text = [
      "dispatcher 'Krejci Iveta' ready",
      "User 'disp4' (Prochazka Karel) logged",
      'user=Benes Zdenka group=GRP_HAVARIE',
      'initiator=Pospisilova Tomas',
    ].join('\n')
    const matches = run(detectContextualPersons, text)
    expect(matches.map((m) => m.original).sort()).toEqual([
      'Benes Zdenka',
      'Krejci Iveta',
      'Pospisilova Tomas',
      'Prochazka Karel',
    ])
  })

  it('detects MP_/GRP_/tenant internal ids', () => {
    const text = "MP_PRA GRP_VELITEL tenant 'Krajska Sprava Silnic Plzen'"
    const matches = run(detectContextualIdentifiers, text)
    expect(matches.map((m) => m.original).sort()).toEqual([
      'GRP_VELITEL',
      'Krajska Sprava Silnic Plzen',
      'MP_PRA',
    ])
  })

  it('detects ports after IPv4 and in port= keywords without matching clock times', () => {
    const text = 'connect 10.0.0.5:5060 ok; port=12345; time 10:16:01'
    const matches = run(detectPorts, text)
    expect(matches.map((m) => m.original).sort()).toEqual(['12345', ':5060'])
    expect(matches.every((m) => m.category === 'port')).toBe(true)
  })

  it('detects custom literal and regex with high priority', () => {
    const config: DetectorConfig = {
      ...DEFAULT_DETECTOR_CONFIG,
      customRules: [
        {
          id: 'r1',
          name: 'secret',
          kind: 'literal',
          pattern: 'SECRET_TOKEN',
          category: 'custom',
          enabled: true,
          priority: 1000,
          replacementMode: 'fixed',
          fixedReplacement: 'REDACTED',
        },
        {
          id: 'r2',
          name: 'code',
          kind: 'regex',
          pattern: 'CODE-\\d+',
          category: 'custom',
          enabled: true,
          priority: 1001,
          caseSensitive: true,
          replacementMode: 'auto',
        },
      ],
    }
    const matches = run(detectCustomRules, 'SECRET_TOKEN and CODE-42', config)
    expect(matches.map((m) => m.original).sort()).toEqual(['CODE-42', 'SECRET_TOKEN'])
  })
})
