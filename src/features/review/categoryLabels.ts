/** Czech labels for entity categories (ARCHITECTURE §3.3). */
import type { Category } from '../../domain/types.ts'

export const CATEGORY_LABELS: Record<Category, string> = {
  ip: 'IP adresy',
  hostname: 'Hostitelé',
  'sip-phone': 'SIP / telefon',
  email: 'E-maily',
  person: 'Osoby',
  'user-id': 'Uživatelská ID',
  'internal-id': 'Interní ID',
  port: 'Porty',
  custom: 'Vlastní',
}
