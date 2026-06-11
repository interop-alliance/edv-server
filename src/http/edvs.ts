/**
 * Vault (EDV config) routes: create, find by reference, get, update.
 *
 * Authorization for creation is self-provisioning (no metering): the root
 * zcap for `POST /edvs` is synthesized with controller := the posted
 * `config.controller`. `GET /edvs?controller=...` uses the `controller`
 * query param as root controller (bedrock parity). Holding the matching
 * signing key is what makes the self-claimed controller meaningful.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { IEDVConfig } from '@interop/data-integrity-core'
import type { ResolvedEdvOptions } from '../config.js'
import { DataError, EdvError } from '../errors.js'
import { generateLocalId } from '../helpers.js'
import { getConfigsQuery, postConfigBody } from '../schemas.js'
import { findConfigs, insertConfig, updateConfig } from '../storage/edvs.js'
import { authorizeInvocation } from '../zcap/authorize.js'
import { makeEdvAuthorize, makeEdvContext } from './edv-context.js'

export function registerEdvRoutes({
  fastify,
  opts
}: {
  fastify: FastifyInstance
  opts: ResolvedEdvOptions
}): void {
  const { routePrefix, edvBaseUrl, dataDir } = opts
  const edvContext = makeEdvContext({ opts })

  // create a new EDV; the poster's own `controller` is the root controller
  fastify.post(routePrefix, {
    schema: { body: postConfigBody },
    preHandler: [
      async function authorizeCreate(request: FastifyRequest) {
        const { controller } = request.body as IEDVConfig
        await authorizeInvocation({
          request,
          baseUrl: opts.baseUrl,
          expectedAction: 'write',
          rootTargets: new Map([[edvBaseUrl, controller]])
        })
      }
    ],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const body = request.body as IEDVConfig
      // do not allow client to choose the EDV ID
      delete body.id
      if (body.sequence !== 0) {
        throw new DataError({
          message:
            'Could not create encrypted data vault; ' +
            'configuration "sequence" must be "0".'
        })
      }
      const id = `${edvBaseUrl}/${await generateLocalId()}`
      const config: IEDVConfig = { id, ...body }
      await insertConfig({ dataDir, config })
      await reply.status(201).header('location', id).send(config)
    }
  })

  // find configs by controller + referenceId
  fastify.get(routePrefix, {
    schema: { querystring: getConfigsQuery },
    preHandler: [
      async function authorizeFind(request: FastifyRequest) {
        const { controller } = request.query as { controller: string }
        await authorizeInvocation({
          request,
          baseUrl: opts.baseUrl,
          expectedAction: 'read',
          rootTargets: new Map([[edvBaseUrl, controller]])
        })
      }
    ],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const { controller, referenceId } = request.query as {
        controller: string
        referenceId: string
      }
      const configs = await findConfigs({ dataDir, controller, referenceId })
      await reply.send(configs)
    }
  })

  // get an EDV config
  fastify.get(`${routePrefix}/:edvId`, {
    preHandler: [edvContext, makeEdvAuthorize({ opts })],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      await reply.send(request.edv!.config)
    }
  })

  // update an EDV config
  fastify.post(`${routePrefix}/:edvId`, {
    schema: { body: postConfigBody },
    preHandler: [edvContext, makeEdvAuthorize({ opts })],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const config = request.body as IEDVConfig
      const { config: existingConfig } = request.edv!
      if (existingConfig.id !== config.id) {
        throw new EdvError({
          message: 'Configuration "id" does not match.',
          name: 'URLMismatchError',
          httpStatusCode: 400
        })
      }
      // prevent changing `referenceId`
      if (existingConfig.referenceId !== config.referenceId) {
        throw new EdvError({
          message: 'Reference ID does not match.',
          name: 'ConflictError',
          httpStatusCode: 400
        })
      }
      await updateConfig({ dataDir, config })
      await reply.send({ config })
    }
  })
}
