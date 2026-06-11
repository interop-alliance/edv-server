/**
 * The revocation-checking hook threaded into every capability
 * verification: rejects a chain when any of its non-root capability IDs is
 * in the vault's revocation set.
 */
import type { InspectCapabilityChain } from '@interop/zcap'
import { getRevokedIds } from '../storage/revocations.js'
import { ZCAP_ROOT_PREFIX } from './loader.js'

/**
 * Creates an `inspectCapabilityChain` hook bound to one vault's revocation
 * set.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @returns {InspectCapabilityChain}
 */
export function makeInspectCapabilityChain({
  dataDir,
  localEdvId
}: {
  dataDir: string
  localEdvId: string
}): InspectCapabilityChain {
  return async function inspectCapabilityChain({ capabilityChain }) {
    const revokedIds = await getRevokedIds({ dataDir, localEdvId })
    for (const capability of capabilityChain) {
      // root zcaps are synthesized and cannot be revoked
      if (capability.id.startsWith(ZCAP_ROOT_PREFIX)) {
        continue
      }
      if (revokedIds.has(capability.id)) {
        const error = new Error(
          `The capability "${capability.id}" has been revoked.`
        )
        error.name = 'NotAllowedError'
        return { valid: false, error }
      }
    }
    return { valid: true }
  }
}
