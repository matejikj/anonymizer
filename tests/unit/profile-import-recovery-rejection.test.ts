import { describe, expect, it } from 'vitest'
import { cs } from '../../src/i18n/cs.ts'

describe('profile import — recovery bundle rejection', () => {
  it('rejects a recovery bundle pasted as a text profile', async () => {
    const { buildImportPreview } = await import('../../src/features/profiles/profileController.ts')
    const result = await buildImportPreview(`RNDPCAPR${String.fromCharCode(0)}not-json`)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.issues[0]?.code).toBe('recovery-bundle')
    expect(result.issues[0]?.message).toBe(cs.profiles.importRecoveryRejected)
  })
})
