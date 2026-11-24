/**
 * T61 — pinned 5G SBI OpenAPI operation inventory (REL-18 offline subset).
 * Normative refs: TS 29.500 v18.9.0, TS 29.571 v18.8.0, 3GPP Forge REL-18.
 * No runtime remote $ref / schema fetch — descriptors are compile-time only.
 */

export type SbiApiFamily =
  | 'nnrf'
  | 'namf'
  | 'nsmf'
  | 'nudm'
  | 'nausf'
  | 'npcf'
  | 'nnssf'
  | 'nnef'
  | 'unknown'

export type SbiFieldAction = 'preserve' | 'map-opaque' | 'map-imsi' | 'map-ipv4' | 'map-hostname' | 'mask'

export interface SbiPinnedOperation {
  readonly family: SbiApiFamily
  readonly service: string
  readonly operationId: string
  readonly method: string
  readonly pathPattern: string
  readonly ts: string
}

/** T61.1–T61.4 baseline coverage — not a claim of full REL-18 surface. */
export const SBI_PINNED_OPERATIONS: readonly SbiPinnedOperation[] = [
  // T61.1 NRF
  {
    family: 'nnrf',
    service: 'nnrf-nfm',
    operationId: 'RegisterNFInstance',
    method: 'PUT',
    pathPattern: '/nnrf-nfm/v1/nf-instances/{nfInstanceID}',
    ts: 'TS29.510',
  },
  {
    family: 'nnrf',
    service: 'nnrf-disc',
    operationId: 'SearchNFInstances',
    method: 'GET',
    pathPattern: '/nnrf-disc/v1/nf-instances',
    ts: 'TS29.510',
  },
  {
    family: 'nnrf',
    service: 'nnrf-oauth2',
    operationId: 'AccessTokenRequest',
    method: 'POST',
    pathPattern: '/oauth2/token',
    ts: 'TS29.510',
  },
  // T61.2 AMF / SMF
  {
    family: 'namf',
    service: 'namf-comm',
    operationId: 'N1N2MessageTransfer',
    method: 'POST',
    pathPattern: '/namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages',
    ts: 'TS29.518',
  },
  {
    family: 'namf',
    service: 'namf-evts',
    operationId: 'CreateSubscription',
    method: 'POST',
    pathPattern: '/namf-evts/v1/subscriptions',
    ts: 'TS29.518',
  },
  {
    family: 'nsmf',
    service: 'nsmf-pdusession',
    operationId: 'CreateSmContext',
    method: 'POST',
    pathPattern: '/nsmf-pdusession/v1/sm-contexts',
    ts: 'TS29.502',
  },
  {
    family: 'nsmf',
    service: 'nsmf-pdusession',
    operationId: 'UpdateSmContext',
    method: 'POST',
    pathPattern: '/nsmf-pdusession/v1/sm-contexts/{smContextRef}/modify',
    ts: 'TS29.502',
  },
  {
    family: 'nsmf',
    service: 'nsmf-pdusession',
    operationId: 'ReleaseSmContext',
    method: 'POST',
    pathPattern: '/nsmf-pdusession/v1/sm-contexts/{smContextRef}/release',
    ts: 'TS29.502',
  },
  // T61.3 UDM / AUSF
  {
    family: 'nudm',
    service: 'nudm-sdm',
    operationId: 'GetSupi',
    method: 'GET',
    pathPattern: '/nudm-sdm/v2/{supi}',
    ts: 'TS29.503',
  },
  {
    family: 'nudm',
    service: 'nudm-uecm',
    operationId: 'RegistrationAmf3GppAccess',
    method: 'PUT',
    pathPattern: '/nudm-uecm/v1/{ueId}/registrations/amf-3gpp-access',
    ts: 'TS29.503',
  },
  {
    family: 'nausf',
    service: 'nausf-auth',
    operationId: 'UeAuthenticationsPost',
    method: 'POST',
    pathPattern: '/nausf-auth/v1/ue-authentications',
    ts: 'TS29.509',
  },
  // T61.4 PCF / NSSF / NEF
  {
    family: 'npcf',
    service: 'npcf-smpolicycontrol',
    operationId: 'CreateSMPolicy',
    method: 'POST',
    pathPattern: '/npcf-smpolicycontrol/v1/sm-policies',
    ts: 'TS29.512',
  },
  {
    family: 'nnssf',
    service: 'nnssf-nsselection',
    operationId: 'NSSelectionGet',
    method: 'GET',
    pathPattern: '/nnssf-nsselection/v1/network-slice-information',
    ts: 'TS29.531',
  },
  {
    family: 'nnef',
    service: 'nnef-eventexposure',
    operationId: 'CreateEventSubscription',
    method: 'POST',
    pathPattern: '/nnef-eventexposure/v1/subscriptions',
    ts: 'TS29.522',
  },
] as const

/** Offline pin label for release inventory (not a full Forge commit hash claim). */
export const SBI_SCHEMA_PIN = {
  release: 'REL-18',
  commonTypes: 'TS29.571/18.8.0',
  commonProc: 'TS29.500/18.9.0',
  forgeLabel: '3GPP Forge REL-18 (pinned local subset; no remote load)',
} as const

const PATH_FAMILY_RE =
  /\/(?:nnrf-[a-z0-9-]+|namf-[a-z0-9-]+|nsmf-[a-z0-9-]+|nudm-[a-z0-9-]+|nausf-[a-z0-9-]+|npcf-[a-z0-9-]+|nnssf-[a-z0-9-]+|nnef-[a-z0-9-]+|oauth2\/token)/i

export function looksLikeSbiPath(pathOrUrl: string): boolean {
  return PATH_FAMILY_RE.test(pathOrUrl)
}

export function sbiFamilyFromPath(pathOrUrl: string): SbiApiFamily {
  const m = /\/(nnrf|namf|nsmf|nudm|nausf|npcf|nnssf|nnef)-/i.exec(pathOrUrl)
  if (m) return m[1]!.toLowerCase() as SbiApiFamily
  if (/\/oauth2\/token/i.test(pathOrUrl)) return 'nnrf'
  return 'unknown'
}

/** JSON / URI key → field action (TS29.571 common types + service overlays). */
export const SBI_FIELD_POLICY: ReadonlyMap<string, SbiFieldAction> = new Map([
  // Preserve diagnostics
  ['status', 'preserve'],
  ['cause', 'preserve'],
  ['problem', 'preserve'],
  ['type', 'preserve'],
  ['title', 'mask'],
  ['detail', 'mask'],
  ['instance', 'map-opaque'],
  ['5qi', 'preserve'],
  ['qi', 'preserve'],
  ['priorityLevel', 'preserve'],
  ['preemptCap', 'preserve'],
  ['preemptVuln', 'preserve'],
  ['sst', 'preserve'],
  ['sd', 'map-opaque'],
  // Subscriber / UE
  ['supi', 'map-imsi'],
  ['supiOrSuci', 'map-imsi'],
  ['gpsi', 'map-opaque'],
  ['pei', 'map-opaque'],
  ['suci', 'map-opaque'],
  ['ueId', 'map-opaque'],
  ['ueContextId', 'map-opaque'],
  ['guti', 'map-opaque'],
  ['5gGuti', 'map-opaque'],
  // NF / session graph
  ['nfInstanceId', 'map-opaque'],
  ['nfInstanceID', 'map-opaque'],
  ['nfSetId', 'map-opaque'],
  ['nfServiceSetId', 'map-opaque'],
  ['subscriptionId', 'map-opaque'],
  ['smContextRef', 'map-opaque'],
  ['smContextStatusUri', 'map-hostname'],
  ['pduSessionId', 'map-opaque'],
  ['pduSessionRef', 'map-opaque'],
  ['correlationId', 'map-opaque'],
  ['callbackReference', 'map-hostname'],
  ['notificationUri', 'map-hostname'],
  ['notificationDestination', 'map-hostname'],
  ['targetApiRoot', 'map-hostname'],
  ['apiRoot', 'map-hostname'],
  ['fqdn', 'map-hostname'],
  ['ipv4Address', 'map-ipv4'],
  ['ipv6Address', 'map-opaque'],
  ['dnn', 'map-opaque'],
  ['servingNetwork', 'map-opaque'],
  ['plmnId', 'map-opaque'],
  ['guami', 'map-opaque'],
  ['amfId', 'map-opaque'],
  // Secrets / auth (always mask)
  ['accessToken', 'mask'],
  ['access_token', 'mask'],
  ['token', 'mask'],
  ['authorization', 'mask'],
  ['client_secret', 'mask'],
  ['clientSecret', 'mask'],
  ['rand', 'mask'],
  ['autn', 'mask'],
  ['xres', 'mask'],
  ['xresStar', 'mask'],
  ['hxres', 'mask'],
  ['hxresStar', 'mask'],
  ['kseaf', 'mask'],
  ['kausf', 'mask'],
  ['authResult', 'preserve'],
  // Location
  ['nrLocation', 'mask'],
  ['eutraLocation', 'mask'],
  ['n3gaLocation', 'mask'],
  ['geographicArea', 'mask'],
  ['civicAddress', 'mask'],
  ['tai', 'mask'],
  ['ncgi', 'mask'],
  ['ecgi', 'mask'],
  ['ueLocation', 'mask'],
  ['userLocation', 'mask'],
])
