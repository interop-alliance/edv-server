/**
 * The fastify plugin (routes + error handling + CORS) and the
 * `createApp()` convenience factory for running the EDV server
 * standalone.
 */
import { fastify as createFastify } from 'fastify'
import type {
  FastifyError,
  FastifyInstance,
  FastifyPluginAsync,
  FastifyServerOptions
} from 'fastify'
import cors from '@fastify/cors'
import { type EdvPluginOptions, resolveOptions } from './config.js'
import { EdvError } from './errors.js'
import { registerEdvRoutes } from './http/edvs.js'
import { registerDocRoutes } from './http/docs.js'
import { registerChunkRoutes } from './http/chunks.js'
import { registerRevocationRoutes } from './http/revocations.js'

/**
 * The EDV fastify plugin. Registers all EDV routes under
 * `options.routePrefix` (default `/edvs`), a CORS policy, and an error
 * handler that maps EdvError to `{name, message}` JSON.
 *
 * Note: CORS on every endpoint is safe because authorization uses HTTP
 * signatures + capabilities, never cookies, so CSRF is impossible.
 */
export const edvPlugin: FastifyPluginAsync<EdvPluginOptions> =
  async function edvPlugin(fastify, options) {
    const opts = resolveOptions(options)

    // `86400` is the max acceptable preflight cache age for modern browsers
    await fastify.register(cors, { maxAge: 86400 })

    fastify.setErrorHandler(function handleError(
      error: unknown,
      request,
      reply
    ) {
      if (error instanceof EdvError) {
        return reply
          .status(error.httpStatusCode)
          .send({ name: error.name, message: error.message })
      }
      const fastifyError = error as FastifyError
      if (fastifyError.validation) {
        return reply
          .status(400)
          .send({ name: 'ValidationError', message: fastifyError.message })
      }
      const statusCode =
        typeof fastifyError.statusCode === 'number' &&
        fastifyError.statusCode >= 400
          ? fastifyError.statusCode
          : 500
      if (statusCode >= 500) {
        request.log.error(error)
      }
      return reply.status(statusCode).send({
        name: fastifyError.name || 'InternalServerError',
        message: fastifyError.message
      })
    })

    registerEdvRoutes({ fastify, opts })
    registerDocRoutes({ fastify, opts })
    registerChunkRoutes({ fastify, opts })
    registerRevocationRoutes({ fastify, opts })
  }

/**
 * Creates a standalone fastify app with the EDV plugin registered.
 *
 * @param options {object}
 * @param options.baseUrl {string}   public base URL (must match how
 *   clients reach the server; used for EDV IDs and zcap target checks)
 * @param options.dataDir {string}   filesystem storage directory
 * @param [options.routePrefix] {string}   default '/edvs'
 * @param [options.fastifyOptions] {FastifyServerOptions}   extra fastify
 *   server options (e.g. `logger`)
 * @returns {FastifyInstance}
 */
export function createApp({
  baseUrl,
  dataDir,
  routePrefix,
  fastifyOptions = {}
}: EdvPluginOptions & {
  fastifyOptions?: FastifyServerOptions
}): FastifyInstance {
  const app = createFastify({
    // additionalProperties: false in the schemas must reject (not strip)
    // unknown properties, matching the reference implementation; type
    // coercion must be off so validation never mutates a request body
    // (the digest check compares the body to what the client signed)
    ajv: {
      customOptions: {
        removeAdditional: false,
        coerceTypes: false,
        // the delegated zcap schema uses a union type for chain items
        allowUnionTypes: true
      }
    },
    ...fastifyOptions
  })
  app.register(edvPlugin, { baseUrl, dataDir, routePrefix })
  return app
}
