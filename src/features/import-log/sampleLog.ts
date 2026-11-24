/**
 * Embedded demo log — offline, no network fetch (ARCHITECTURE §3.1 / §12).
 */
export const SAMPLE_LOG = `\
2026-08-10 06:30:08.152 [main] INFO  LoginController - User 'disp4' (Prochazka Karel) logged in from workstation konosdot-ws07-brn.local
2026-08-10 06:30:09.001 [sip] INFO  CallControl - INVITE sip:972051127@10.37.63.169:5060 from sip:disp4@10.16.1.105
2026-08-10 06:30:09.440 [http] INFO  TenantService - binding tenant 'Krajska Sprava Silnic Plzen' to MP_PRA
2026-08-10 06:30:10.112 [audit] INFO  AccessLog - dispatcher 'Krejci Iveta' joined group=GRP_HAVARIE
2026-08-10 06:30:11.002 [ldap] INFO  DirSync - lookup ldap-pra.corp.example user=Benes Zdenka
2026-08-10 06:30:12.500 [gw] INFO  RgwSession - peer 10.11.1.10 via rgw01-pra.vaf.local initiator=Pospisilova Tomas
2026-08-10 06:30:13.010 [media] INFO  Conference - member sip:7123451300@10.12.1.101 GRP_VELITEL
2026-08-10 06:30:14.777 [as] INFO  JwtUtil - Issued JWT for user 'disp22' (Horakova Karel), roles=[DISPATCHER]
`.trimStart()
