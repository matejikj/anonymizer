import type { Page } from '@playwright/test'

type FilePayload = {
  name: string
  mimeType: string
  buffer: Buffer
}

/** Load one or more files through the universal header file picker. */
export async function loadUniversalFiles(
  page: Page,
  files: string | FilePayload | readonly (string | FilePayload)[],
): Promise<void> {
  const list = Array.isArray(files) ? files : [files]
  await page.getByTestId('persistent-file-input').setInputFiles(list as string & FilePayload)
}
