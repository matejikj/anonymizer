import { loadPreference, savePreference } from '../persistence/preferencesRepository.ts'

export function isOnboardingComplete(): boolean {
  return loadPreference('onboardingComplete', false)
}

export function markOnboardingComplete(): void {
  savePreference('onboardingComplete', true)
}

export function resetOnboardingForTests(): void {
  savePreference('onboardingComplete', false)
}
