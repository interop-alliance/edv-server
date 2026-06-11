/**
 * The `request.edv` context: a preHandler that loads the vault config for
 * `/edvs/:edvId/**` routes (404 if absent) before authorization runs --
 * the config *is* the authority source (its `controller` is the root zcap
 * controller for the vault).
 */
import type { FastifyRequest, preHandlerAsyncHookHandler } from 'fastify'
import type { IEDVConfig } from '@interop/data-integrity-core'
import type { ResolvedEdvOptions } from '../config.js'
import { getConfig } from '../storage/edvs.js'
import { authorizeInvocation } from '../zcap/authorize.js'
import { makeInspectCapabilityChain } from '../zcap/inspect-chain.js'

export interface EdvRequestContext {
  config: IEDVConfig
  localEdvId: string
  /** The vault's full URL (`config.id`). */
  edvUrl: string
}

declare module 'fastify' {
  interface FastifyRequest {
    edv?: EdvRequestContext
  }
}

/**
 * Creates the preHandler that loads the EDV config for the request's
 * `:edvId` param into `request.edv`.
 *
 * @param options {object}
 * @param options.opts {ResolvedEdvOptions}
 * @returns {preHandlerAsyncHookHandler}
 */
export function makeEdvContext({
  opts
}: {
  opts: ResolvedEdvOptions
}): preHandlerAsyncHookHandler {
  return async function loadEdvContext(request: FastifyRequest) {
    const { edvId } = request.params as { edvId: string }
    const config = await getConfig({
      dataDir: opts.dataDir,
      localEdvId: edvId
    })
    request.edv = { config, localEdvId: edvId, edvUrl: config.id! }
  }
}

/**
 * Creates the zcap authorization preHandler for `/edvs/:edvId/**` routes:
 * root invocation target = the vault URL, root controller = the stored
 * config's `controller`, expected action derived from the HTTP method
 * (GET = read, others = write) unless overridden. Revocation checking is
 * threaded in via the vault-bound `inspectCapabilityChain` hook. Must run
 * after the `makeEdvContext` preHandler.
 *
 * @param options {object}
 * @param options.opts {ResolvedEdvOptions}
 * @param [options.expectedAction] {string}   override (the query routes
 *   are POSTs that require only `read`)
 * @returns {preHandlerAsyncHookHandler}
 */
export function makeEdvAuthorize({
  opts,
  expectedAction
}: {
  opts: ResolvedEdvOptions
  expectedAction?: string
}): preHandlerAsyncHookHandler {
  return async function authorizeEdvInvocation(request: FastifyRequest) {
    const { config, localEdvId, edvUrl } = request.edv!
    await authorizeInvocation({
      request,
      baseUrl: opts.baseUrl,
      expectedAction:
        expectedAction ??
        (request.method === 'GET' || request.method === 'HEAD'
          ? 'read'
          : 'write'),
      rootTargets: new Map([[edvUrl, config.controller]]),
      inspectCapabilityChain: makeInspectCapabilityChain({
        dataDir: opts.dataDir,
        localEdvId
      })
    })
  }
}
