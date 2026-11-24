/**
 * Stable error/issue codes with typed parameters (Stage 16).
 * UI/i18n maps codes to Czech strings; controllers branch on code, not message text.
 */

export const PreflightIssueCode = {
  TooLarge: 'too-large',
  TooSmall: 'too-small',
  UnknownFormat: 'unknown-format',
  Aborted: 'aborted',
} as const
export type PreflightIssueCode = (typeof PreflightIssueCode)[keyof typeof PreflightIssueCode]

export const WorkerIssueCode = {
  Cancelled: 'cancelled',
  RegexTimeout: 'regex-timeout',
  InvalidChunk: 'invalid-chunk',
  Internal: 'internal',
  LineLimit: 'line-limit',
  InvalidProtocolVersion: 'invalid-protocol-version',
  StaleGeneration: 'stale-generation',
  InvalidMessage: 'invalid-message',
  ParseFailed: 'parse-failed',
  PlanRejected: 'plan-rejected',
} as const
export type WorkerIssueCode = (typeof WorkerIssueCode)[keyof typeof WorkerIssueCode]

export interface TypedIssue<TCode extends string = string> {
  readonly code: TCode
  readonly message: string
}

export interface PreflightIssue extends TypedIssue<PreflightIssueCode> {
  readonly byteLength?: number
}

export function isWorkerIssueCode(code: string): code is WorkerIssueCode {
  return Object.values(WorkerIssueCode).includes(code as WorkerIssueCode)
}
