import { describe, expect, it } from 'vitest'
import { resolveSessionStepView } from '../../src/app/sessionStepModel.ts'

describe('sessionStepModel', () => {
  it('hides stepper on empty landing', () => {
    expect(resolveSessionStepView('empty', 'empty', false).visible).toBe(false)
  })

  it('maps correlation staging to files step', () => {
    const view = resolveSessionStepView('correlation-staging', 'empty', false)
    expect(view.visible).toBe(true)
    expect(view.activeStep).toBe('files')
  })

  it('shows analysis/review for standalone PCAP shell', () => {
    expect(resolveSessionStepView('empty', 'analyzing', true).activeStep).toBe('analysis')
    expect(resolveSessionStepView('empty', 'workspace', true).activeStep).toBe('review')
    expect(resolveSessionStepView('empty', 'preflight', true).activeStep).toBe('analysis')
    expect(resolveSessionStepView('empty', 'empty', true).visible).toBe(false)
  })

  it('keeps correlation stepper when PCAP shell mode is active', () => {
    const view = resolveSessionStepView('correlation-review', 'workspace', true)
    expect(view.visible).toBe(true)
    expect(view.activeStep).toBe('review')
  })

  it('maps standalone text import and workspace', () => {
    expect(resolveSessionStepView('importing', 'empty', false).activeStep).toBe('analysis')
    expect(resolveSessionStepView('workspace', 'empty', false).activeStep).toBe('review')
  })

  it('maps correlation review to review step', () => {
    const view = resolveSessionStepView('correlation-review', 'empty', false)
    expect(view.activeStep).toBe('review')
    expect(view.completedBefore.has('analysis')).toBe(true)
  })

  it('maps correlation export phases to export step', () => {
    expect(resolveSessionStepView('correlation-exporting', 'empty', false).activeStep).toBe('export')
    expect(resolveSessionStepView('correlation-completed', 'empty', false).activeStep).toBe('export')
  })
})
