/**
 * Verification of a to-be-revoked zcap's delegation chain, ported from
 * ezcap-express `lib/revoke.js`. The chain is verified with
 * `CapabilityDelegation` (target attenuation always allowed on this
 * endpoint), its root invocation target must be the vault URL or fall
 * under it, and every chain controller plus the delegator are collected so
 * that any chain participant may invoke the revocation endpoint.
 */
import * as jsigs from '@interop/jsonld-signatures'
import { CapabilityDelegation } from '@interop/zcap'
import type { InspectCapabilityChain, InspectResult } from '@interop/zcap'
import type { IDelegatedZcap, IZcap } from '@interop/data-integrity-core'
import { DataError, NotAllowedError } from '../errors.js'
import {
  MAX_CHAIN_LENGTH,
  MAX_CLOCK_SKEW,
  MAX_DELEGATION_TTL
} from './authorize.js'
import { buildDocumentLoader, ZCAP_ROOT_PREFIX, rootZcapId } from './loader.js'
import { createSuite } from './verifier.js'

/**
 * Verifies the delegation chain of a capability submitted for revocation.
 * Returns the delegator and every controller in the chain.
 *
 * @param options {object}
 * @param options.capability {IDelegatedZcap}   the to-be-revoked zcap
 * @param options.edvUrl {string}   the vault URL (the service object ID)
 * @param options.controller {string}   the vault's controller (root
 *   controller for chains rooted at the vault)
 * @param options.revocationTarget {string}   the zcap-specific root target,
 *   `<edvUrl>/zcaps/revocations/<encodeURIComponent(revocationId)>`
 * @param [options.inspectCapabilityChain] {InspectCapabilityChain}
 *   revocation-checking hook (a chain with an already-revoked ancestor
 *   cannot be used to submit further revocations)
 * @returns {Promise<{delegator: string, chainControllers: string[]}>}
 */
export async function verifyRevocationDelegation({
  capability,
  edvUrl,
  controller,
  revocationTarget,
  inspectCapabilityChain
}: {
  capability: IDelegatedZcap
  edvUrl: string
  controller: string
  revocationTarget: string
  inspectCapabilityChain?: InspectCapabilityChain
}): Promise<{ delegator: string; chainControllers: string[] }> {
  // a root capability cannot be revoked
  if (capability.id.startsWith(ZCAP_ROOT_PREFIX)) {
    throw new NotAllowedError({
      message: 'A root capability cannot be revoked.',
      httpStatusCode: 400
    })
  }

  // the root of the to-be-revoked chain must be this vault (or fall under
  // it); this prevents storing revocations for unrelated vaults/services
  const rootTarget = _parseChainRootTarget({ capability })
  if (!(rootTarget === edvUrl || rootTarget.startsWith(`${edvUrl}/`))) {
    throw new NotAllowedError({
      message:
        "The root capability from the revocation's delegation chain must " +
        `have an invocation target that starts with "${edvUrl}".`
    })
  }

  const documentLoader = buildDocumentLoader({
    getRootController({ target }) {
      if (target === edvUrl || target.startsWith(`${edvUrl}/`)) {
        return controller
      }
      return null
    }
  })

  // collect every controller in the chain while inspecting it
  const chainControllers: string[] = []
  async function captureChainControllers({
    capabilityChain,
    capabilityChainMeta
  }: {
    capabilityChain: IZcap[]
    capabilityChainMeta: never[]
  }): Promise<InspectResult> {
    for (const chainCapability of capabilityChain) {
      const { controller: chainController } = chainCapability
      if (Array.isArray(chainController)) {
        chainControllers.push(...chainController)
      } else if (chainController) {
        chainControllers.push(chainController)
      }
    }
    if (inspectCapabilityChain) {
      return inspectCapabilityChain({ capabilityChain, capabilityChainMeta })
    }
    return { valid: true }
  }

  const suite = createSuite()
  const { verified, error, results } = await jsigs.verify(capability, {
    documentLoader,
    purpose: new CapabilityDelegation({
      // path-based target attenuation is always allowed on this endpoint:
      // zcaps delegated with attenuation rules an invocation endpoint may
      // not support can still be revoked
      allowTargetAttenuation: true,
      expectedRootCapability: [
        rootZcapId({ target: edvUrl }),
        rootZcapId({ target: revocationTarget })
      ],
      inspectCapabilityChain: captureChainControllers as InspectCapabilityChain,
      maxChainLength: MAX_CHAIN_LENGTH,
      maxClockSkew: MAX_CLOCK_SKEW,
      maxDelegationTtl: MAX_DELEGATION_TTL,
      suite
    }),
    suite
  })
  if (!verified) {
    throw new DataError({
      message: 'The provided capability delegation is invalid.',
      cause: error
    })
  }

  // the delegator of the revoked zcap, from the verified delegation proof
  const purposeResult = results[0]?.purposeResult as
    | { delegator?: { id?: string } | string }
    | undefined
  let delegator = purposeResult?.delegator ?? ''
  if (typeof delegator === 'object') {
    delegator = delegator.id ?? ''
  }
  return { delegator, chainControllers }
}

function _parseChainRootTarget({
  capability
}: {
  capability: IDelegatedZcap
}): string {
  const proofs = Array.isArray(capability.proof)
    ? capability.proof
    : [capability.proof]
  const chain = proofs[0]?.capabilityChain
  const root = chain?.[0]
  const rootId =
    typeof root === 'string' ? root : (root as { id?: string } | undefined)?.id
  if (typeof rootId !== 'string' || !rootId.startsWith(ZCAP_ROOT_PREFIX)) {
    throw new DataError({
      message:
        'The provided capability delegation has no root capability in its ' +
        'capability chain.'
    })
  }
  return decodeURIComponent(rootId.slice(ZCAP_ROOT_PREFIX.length))
}
