/**
 * Document loader factory for zcap verification. Wraps
 * `@interop/security-document-loader` (static security contexts + did:key
 * resolution) with a `urn:` protocol handler that synthesizes root zcaps on
 * demand: `urn:zcap:root:<encoded target>` resolves to a root capability
 * whose controller is supplied by the caller's `getRootController` hook.
 */
import { securityLoader } from '@interop/security-document-loader'
import type { IDocumentLoader } from '@interop/data-integrity-core/loader'

export const ZCAP_ROOT_PREFIX = 'urn:zcap:root:'

/**
 * Returns the controller(s) for a root capability with the given
 * invocation target, or null if no root capability exists for it.
 */
export type GetRootController = (options: {
  target: string
}) => string | string[] | null

/**
 * Builds a document loader that synthesizes root zcaps via the given
 * controller hook.
 *
 * @param options {object}
 * @param options.getRootController {GetRootController}
 * @returns {IDocumentLoader}
 */
export function buildDocumentLoader({
  getRootController
}: {
  getRootController: GetRootController
}): IDocumentLoader {
  const loader = securityLoader()
  loader.setProtocolHandler({
    protocol: 'urn',
    handler: {
      get: async ({ id, url }: { id?: string; url?: string }) => {
        const resolvedUrl = url ?? id
        if (!resolvedUrl || !resolvedUrl.startsWith(ZCAP_ROOT_PREFIX)) {
          throw new Error(`Document not found: "${resolvedUrl}".`)
        }
        const target = decodeURIComponent(
          resolvedUrl.slice(ZCAP_ROOT_PREFIX.length)
        )
        const controller = getRootController({ target })
        if (controller === null) {
          throw new Error(`Root capability not found: "${resolvedUrl}".`)
        }
        return {
          '@context': 'https://w3id.org/zcap/v1',
          id: resolvedUrl,
          invocationTarget: target,
          controller
        }
      }
    }
  })
  return loader.build()
}

/**
 * Builds the conventional root zcap ID for an invocation target.
 *
 * @param options {object}
 * @param options.target {string}   the invocation target URL
 * @returns {string}
 */
export function rootZcapId({ target }: { target: string }): string {
  return `${ZCAP_ROOT_PREFIX}${encodeURIComponent(target)}`
}
