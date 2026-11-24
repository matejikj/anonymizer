/**
 * Merge length-preserving patches without silently dropping collisions (step 2).
 */

import type { BytePatch } from '../sanitize/types'
import { PatchCollector } from '../sanitize/PatchCollector'
import { MappingPatchError } from '../anonymization/mappingErrors'
import { PlanInvariantError } from './planErrors'

export function mergePatchesStrict(
  bufferLength: number,
  packetIndex: number,
  patches: Iterable<Pick<BytePatch, 'offset' | 'data'>>,
): BytePatch[] {
  const collector = new PatchCollector(bufferLength)
  for (const patch of patches) {
    try {
      collector.add(patch.offset, patch.data)
    } catch (error) {
      // T03: never embed err.message (may carry identity-bearing detail from lower layers).
      const causeCode = error instanceof MappingPatchError ? error.code : 'patch-overlap'
      throw new PlanInvariantError({
        code: 'patch-overlap',
        message: `Patch collision (packetIndex=${packetIndex}, reason=${causeCode})`,
        packetIndex,
        causeCode,
      })
    }
  }
  return collector.getPatches()
}
