/**
 * Capability-invocation authorization for EDV routes. Ports the
 * ezcap-express expected-value pattern: `expectedTarget` is the full
 * request URL, `allowTargetAttenuation: true`, and
 * `expectedRootCapability` is the urn(s) of the root invocation target(s)
 * supplied per route. Also verifies the `digest` header against the parsed
 * request body (which the underlying HTTP-signature check alone does not).
 */
import type { FastifyRequest } from 'fastify'
import {
  verifyCapabilityInvocation,
  type VerifyCapabilityInvocationResult
} from '@interop/http-signature-zcap-verify'
import type { InspectCapabilityChain } from '@interop/zcap'
import { verifyHeaderValue } from '@interop/http-digest-header'
import { DataError, NotAllowedError } from '../errors.js'
import { buildDocumentLoader, rootZcapId } from './loader.js'
import { createSuite, getVerifier } from './verifier.js'

/** Default zcap chain limits (bedrock parity). */
export const MAX_CHAIN_LENGTH = 10
export const MAX_CLOCK_SKEW = 300
export const MAX_DELEGATION_TTL = 365 * 24 * 60 * 60 * 1000

/**
 * Authorizes a zcap-invoked request, or throws (403 on verification
 * failure, 400 on digest mismatch).
 *
 * @param options {object}
 * @param options.request {FastifyRequest}   the request to authorize
 * @param options.baseUrl {string}   the server's public base URL; the full
 *   request URL (expectedTarget) is resolved against it
 * @param options.expectedAction {string}   'read' or 'write'
 * @param options.rootTargets {Map<string, string|string[]>}   root
 *   invocation target URL(s) mapped to their root controller(s); their
 *   urn:zcap:root forms become the expectedRootCapability values
 * @param [options.inspectCapabilityChain] {InspectCapabilityChain}
 *   revocation-checking hook, called with the dereferenced chain
 * @returns {Promise<VerifyCapabilityInvocationResult>}
 */
export async function authorizeInvocation({
  request,
  baseUrl,
  expectedAction,
  rootTargets,
  inspectCapabilityChain
}: {
  request: FastifyRequest
  baseUrl: string
  expectedAction: string
  rootTargets: Map<string, string | string[]>
  inspectCapabilityChain?: InspectCapabilityChain
}): Promise<VerifyCapabilityInvocationResult> {
  // digest-vs-body check: the HTTP signature covers the digest header, but
  // comparing the digest to the actual body is the server's job
  await _verifyDigest({ request })

  const url = new URL(request.raw.url ?? request.url, baseUrl).toString()
  const expectedRootCapability = [...rootTargets.keys()].map(target =>
    rootZcapId({ target })
  )
  const documentLoader = buildDocumentLoader({
    getRootController({ target }) {
      return rootTargets.get(target) ?? null
    }
  })

  let result: VerifyCapabilityInvocationResult
  try {
    result = await verifyCapabilityInvocation({
      url,
      method: request.method,
      headers: request.headers as Record<string, string>,
      expectedHost: new URL(baseUrl).host,
      expectedAction,
      expectedRootCapability,
      expectedTarget: url,
      allowTargetAttenuation: true,
      maxChainLength: MAX_CHAIN_LENGTH,
      maxClockSkew: MAX_CLOCK_SKEW,
      maxDelegationTtl: MAX_DELEGATION_TTL,
      inspectCapabilityChain,
      documentLoader,
      getVerifier,
      suite: createSuite()
    })
  } catch (err) {
    throw new NotAllowedError({
      message: 'Authorization error.',
      cause: err as Error
    })
  }
  if (!result.verified) {
    throw new NotAllowedError({
      message: 'Authorization error.',
      cause: result.error
    })
  }
  return result
}

async function _verifyDigest({
  request
}: {
  request: FastifyRequest
}): Promise<void> {
  if (request.body === undefined || request.body === null) {
    return
  }
  const headerValue = request.headers.digest
  if (typeof headerValue !== 'string') {
    throw new DataError({
      message: 'A "digest" header is required when a request body is sent.'
    })
  }
  // Note: this assumes JSON.parse/JSON.stringify round-trips the client's
  // body bytes (the same assumption ezcap-express makes)
  const { verified } = await verifyHeaderValue({
    data: request.body as object,
    headerValue
  })
  if (!verified) {
    throw new DataError({
      message: 'The "digest" header does not match the request body.'
    })
  }
}
