import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
/** Parent squelch/ directory (fixtures stay there; not copied into anonymizer). */
export const RND_LOG_ANONYMIZER_ROOT = path.resolve(here, '../..', '..')

export const FIXTURE_LOGS = [
  'template-flexcd.log',
  'template-konos-as.log',
  'template-konos-modules.log',
  'template-rgw-server.log',
] as const

export function readFixtureLog(name: (typeof FIXTURE_LOGS)[number]): string {
  const full = path.join(RND_LOG_ANONYMIZER_ROOT, name)
  return fs.readFileSync(full, 'utf8')
}
