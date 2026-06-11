/**
 * Revocation route: `POST /edvs/:edvId/zcaps/revocations/:revocationId`.
 *
 * Order matters (ported from ezcap-express `revoke.js`):
 * 1. reject root zcaps (400);
 * 2. verify the to-be-revoked zcap's delegation chain, collecting every
 *    chain controller and the delegator;
 * 3. verify the HTTP invocation, where the zcap-specific root capability
 *    (`<edvUrl>/zcaps/revocations/<revocationId>`) is controlled by all
 *    chain controllers -- so any chain participant may revoke;
 * 4. store the revocation (consulted by `inspectCapabilityChain` on every
 *    subsequent authorization) and return 204.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { IDelegatedZcap } from '@interop/data-integrity-core'
import type { ResolvedEdvOptions } from '../config.js'
import { postRevocationBody } from '../schemas.js'
import { insertRevocation } from '../storage/revocations.js'
import { authorizeInvocation } from '../zcap/authorize.js'
import { makeInspectCapabilityChain } from '../zcap/inspect-chain.js'
import { verifyRevocationDelegation } from '../zcap/revocation-auth.js'
import { makeEdvContext } from './edv-context.js'

export function registerRevocationRoutes({
  fastify,
  opts
}: {
  fastify: FastifyInstance
  opts: ResolvedEdvOptions
}): void {
  const { routePrefix, dataDir } = opts
  const edvContext = makeEdvContext({ opts })

  fastify.post(`${routePrefix}/:edvId/zcaps/revocations/:revocationId`, {
    schema: { body: postRevocationBody },
    preHandler: [edvContext],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const capability = request.body as IDelegatedZcap
      const { revocationId } = request.params as { revocationId: string }
      const { config, localEdvId, edvUrl } = request.edv!
      const revocationTarget =
        `${edvUrl}/zcaps/revocations/` + encodeURIComponent(revocationId)
      const inspectCapabilityChain = makeInspectCapabilityChain({
        dataDir,
        localEdvId
      })

      // verify the to-be-revoked zcap's delegation chain first; this
      // yields the chain controllers used as the root controller for the
      // zcap-specific root capability in the invocation check below
      const { delegator, chainControllers } = await verifyRevocationDelegation({
        capability,
        edvUrl,
        controller: config.controller,
        revocationTarget,
        inspectCapabilityChain
      })

      await authorizeInvocation({
        request,
        baseUrl: opts.baseUrl,
        expectedAction: 'write',
        rootTargets: new Map<string, string | string[]>([
          [edvUrl, config.controller],
          [revocationTarget, chainControllers]
        ]),
        inspectCapabilityChain
      })

      await insertRevocation({ dataDir, localEdvId, capability, delegator })
      await reply.status(204).send()
    }
  })
}
