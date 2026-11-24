/**
 * T69 — interim free-text vocabulary (expanded B2 stub until T70 bundled artifact).
 *
 * Only words that are demonstrably non-identifying belong here. Given names and
 * device nicknames must NEVER appear — they are free-token / mask targets.
 */

import { isCommonWordAllowlisted } from '../../mapping/commonWordAllowlist.ts'
import type { FreeTextVocabulary } from './types.ts'

/** Protocol / log scaffolding + short function words (EN/CZ technical). */
const EXTRA = [
  // HTTP / SIP / methods
  'get', 'put', 'post', 'head', 'patch', 'delete', 'options', 'trace', 'connect',
  'invite', 'ack', 'bye', 'cancel', 'register', 'refer', 'notify', 'subscribe',
  'publish', 'message', 'prack', 'update', 'info',
  'http', 'https', 'sip', 'sips', 'rtp', 'rtcp', 'tcp', 'udp', 'tls', 'dtls',
  'ws', 'wss', 'mqtt', 'amqp', 'kafka', 'nats', 'stomp', 'xmpp', 'coap',
  'dns', 'dhcp', 'snmp', 'icmp', 'igmp', 'arp', 'lldp', 'ssdp', 'sdp', 'rtp',
  // Status / log levels
  'ok', 'error', 'warn', 'warning', 'debug', 'trace', 'fatal', 'critical',
  'success', 'failed', 'failure', 'timeout', 'retry', 'retries', 'attempt',
  'started', 'stopped', 'starting', 'stopping', 'running', 'idle', 'busy',
  'connected', 'disconnected', 'connecting', 'listening', 'closed', 'closing',
  'request', 'response', 'reply', 'status', 'code', 'reason', 'cause',
  'session', 'dialog', 'transaction', 'packet', 'frame', 'payload', 'header',
  'headers', 'body', 'content', 'length', 'encoding', 'charset', 'mime',
  'application', 'json', 'xml', 'text', 'plain', 'octet', 'stream',
  // Common log scaffolding
  'the', 'and', 'for', 'not', 'are', 'was', 'were', 'been', 'have', 'has',
  'had', 'will', 'can', 'may', 'must', 'should', 'would', 'could', 'did',
  'does', 'doing', 'into', 'from', 'with', 'without', 'about', 'after',
  'before', 'between', 'under', 'over', 'again', 'once', 'only', 'same',
  'other', 'some', 'any', 'all', 'each', 'every', 'both', 'few', 'more',
  'most', 'such', 'than', 'too', 'very', 'just', 'also', 'then', 'when',
  'where', 'what', 'which', 'who', 'whom', 'how', 'why', 'yes', 'no',
  'on', 'off', 'up', 'down', 'out', 'via', 'per', 'new', 'old', 'first',
  'last', 'next', 'prev', 'previous', 'current', 'local', 'remote', 'public',
  'private', 'internal', 'external', 'incoming', 'outgoing', 'inbound',
  'outbound', 'source', 'destination', 'src', 'dst', 'client', 'server',
  'peer', 'node', 'device', 'endpoint', 'channel', 'queue', 'topic', 'group',
  'message', 'event', 'action', 'state', 'mode', 'level', 'version', 'build',
  'config', 'configuration', 'param', 'params', 'parameter', 'parameters',
  'value', 'values', 'key', 'keys', 'field', 'fields', 'record', 'records',
  'file', 'files', 'path', 'paths', 'line', 'lines', 'number', 'count',
  'total', 'size', 'bytes', 'kb', 'mb', 'ms', 'sec', 'secs', 'min', 'mins',
  'hour', 'hours', 'day', 'days', 'time', 'date', 'timestamp', 'duration',
  'address', 'addresses', 'hostname', 'domain', 'uri', 'url', 'urn',
  'protocol', 'service', 'method', 'function', 'module', 'component',
  'process', 'thread', 'worker', 'task', 'job', 'schedule', 'scheduled',
  'enabled', 'disabled', 'active', 'inactive', 'available', 'unavailable',
  'allowed', 'denied', 'accepted', 'rejected', 'pending', 'complete',
  'completed', 'partial', 'full', 'empty', 'missing', 'unknown', 'invalid',
  'valid', 'verified', 'unverified', 'authorized', 'unauthorized',
  // Czech technical / log scaffolding (no given names)
  'chyba', 'varovani', 'informace', 'ladici', 'spusteno', 'zastaveno',
  'pripojeno', 'odpojeno', 'pozadavek', 'odpoved', 'stav', 'kod', 'duvod',
  'relace', 'hovor', 'paket', 'ramec', 'hlavicka', 'telo', 'delka',
  'konfigurace', 'parametr', 'hodnota', 'klic', 'pole', 'zaznam', 'soubor',
  'cesta', 'radek', 'cislo', 'pocet', 'velikost', 'cas', 'datum', 'trvani',
  'adresa', 'protokol', 'sluzba', 'metoda', 'modul', 'proces', 'uloha',
  'povolen', 'zakazan', 'aktivni', 'neaktivni', 'dostupny', 'nedostupny',
  'prijat', 'odmitnut', 'ceka', 'dokonceno', 'neplatny', 'platny',
  'uzivatel', 'stanice', 'system', 'server', 'klient',
  // Short allowlisted function words (≤2) — T70 exclusion carve-out
  'a', 'i', 'o', 'u', 'v', 'k', 's', 'z', 'na', 'do', 'od', 'po', 'za',
  'se', 'si', 'to', 'ta', 'ty', 'je', 'js', 'by', 'az', 'uz', 'uz',
  'an', 'as', 'at', 'be', 'by', 'do', 'if', 'in', 'is', 'it', 'me', 'my',
  'no', 'of', 'on', 'or', 'so', 'to', 'up', 'us', 'we', 'id', 'ip', 'ok',
] as const

const EXTRA_SET = new Set(EXTRA.map((w) => w.toLowerCase()))

export const INTERIM_VOCABULARY_VERSION = 't69-interim-1'

export const interimVocabulary: FreeTextVocabulary = {
  version: INTERIM_VOCABULARY_VERSION,
  has(word: string): boolean {
    const key = word.trim().toLowerCase()
    if (key.length === 0) return false
    if (EXTRA_SET.has(key)) return true
    return isCommonWordAllowlisted(key)
  },
}

/** Default vocabulary for T69 call sites until T70 ships the hashed artifact. */
export function defaultFreeTextVocabulary(): FreeTextVocabulary {
  return interimVocabulary
}
