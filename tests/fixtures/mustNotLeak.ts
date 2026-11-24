/**
 * Explicit must-not-leak token list for fixture integration tests (Krok 2).
 * Curated from rnd-log-anonymizer/template-*.log — anonymized output must contain none of these.
 */
export const MUST_NOT_LEAK = {
  ips: [
    '10.11.1.10',
    '10.16.1.105',
    '10.37.63.169',
    '10.12.1.101',
    '10.13.1.101',
    '127.0.0.1',
  ],
  hostnames: [
    'cucm-pra.corp.example',
    'flexcd-pra.vaf.local',
    'konosas-prod01.corp.example',
    'konosas-prod02.corp.example',
    'konosdot-ws07-brn.local',
    'ldap-brn.corp.example',
    'ldap-pra.corp.example',
    'rgw01-pra.vaf.local',
  ],
  userIds: [
    'disp1',
    'disp5',
    'disp9',
    'disp22',
    'disp24',
  ],
  sipPhones: [
    '972051127',
    '972051117',
    '972051200',
    '7123451300',
    '71234513',
    '71234520',
    '71234521',
    // Short numeric SIP users — check contextual form (bare "121" appears in timestamps/#ids).
    'sip:121@',
    'sip:122@',
  ],
  persons: [
    'Krejci Iveta',
    'Prochazka Karel',
    'Pospisilova Tomas',
    'Bartos Lucie',
    'Benes Zdenka',
    'Horakova Karel',
    'Marek Petra',
  ],
  internalIds: [
    'MP_PRA',
    'MP_BRN',
    'GRP_HAVARIE',
    'GRP_VELITEL',
    'GRP_OSTRAHA',
    'Krajska Sprava Silnic Plzen',
    'Drazni Infrastruktura Sever a.s.',
    'Vltavska Energeticka a.s.',
  ],
} as const

export function allMustNotLeakTokens(): string[] {
  return [
    ...MUST_NOT_LEAK.ips,
    ...MUST_NOT_LEAK.hostnames,
    ...MUST_NOT_LEAK.userIds,
    ...MUST_NOT_LEAK.sipPhones,
    ...MUST_NOT_LEAK.persons,
    ...MUST_NOT_LEAK.internalIds,
  ]
}
