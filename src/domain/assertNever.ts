/**
 * Compile-time exhaustiveness helper for discriminated unions (Stage 16).
 */
export function assertNever(_value: never, context?: string): never {
  // T03: never interpolate the unexpected value — it may carry identity data.
  throw new Error(context ? `Unexpected value in ${context}` : 'Unexpected value')
}
