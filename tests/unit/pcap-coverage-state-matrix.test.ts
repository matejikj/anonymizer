import { describe, expect, it } from 'vitest'
import {
  STAGE6_COVERAGE_STATE_MATRIX,
  STAGE6_USABILITY_TASKS,
} from './pcap-coverage-state-matrix'

describe('Stage 6 design validation artifacts', () => {
  it('documents four level/state cells for coverage UX', () => {
    expect(STAGE6_COVERAGE_STATE_MATRIX).toHaveLength(4)
  })

  it('documents five moderated usability tasks', () => {
    expect(STAGE6_USABILITY_TASKS).toEqual([
      'can-export-safely',
      'find-unsupported-protocol',
      'explain-recognized-vs-protected',
      'remove-active-filter',
      'help-keyboard-only',
    ])
  })
})
