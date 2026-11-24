import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
/** Real template logs live in the gitignored `logs/` dir; tests skip when absent. */
export const FIXTURE_LOGS_DIR = path.resolve(here, '../..', 'logs')

export const FIXTURE_LOGS = [
  'template-edge.log',
  'template-appsrv.log',
  'template-app-modules.log',
  'template-rgw-server.log',
] as const

export function fixtureLogPath(name: (typeof FIXTURE_LOGS)[number]): string {
  return path.join(FIXTURE_LOGS_DIR, name)
}

/** True only when every template log is present locally (they are never committed). */
export const FIXTURE_LOGS_AVAILABLE = FIXTURE_LOGS.every((name) => fs.existsSync(fixtureLogPath(name)))

export function readFixtureLog(name: (typeof FIXTURE_LOGS)[number]): string {
  return fs.readFileSync(fixtureLogPath(name), 'utf8')
}
