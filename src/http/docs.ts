/**
 * Document routes: insert, update (upsert), get, and the two query
 * endpoints (`/query` and `/documents/query`). Query endpoints are POSTs
 * whose expected zcap action is `read`, not `write`.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type {
  IEDVQuery,
  IEncryptedDocument
} from '@interop/data-integrity-core'
import type { ResolvedEdvOptions } from '../config.js'
import { DataError } from '../errors.js'
import { sendCacheableJson } from '../helpers.js'
import { postDocumentBody, postDocumentQueryBody } from '../schemas.js'
import { getDoc, insertDoc, updateDoc } from '../storage/docs.js'
import { countDocs, findDocs } from '../storage/query.js'
import { makeEdvAuthorize, makeEdvContext } from './edv-context.js'

const TEN_MEGABYTES = 10 * 1024 * 1024

export function registerDocRoutes({
  fastify,
  opts
}: {
  fastify: FastifyInstance
  opts: ResolvedEdvOptions
}): void {
  const { routePrefix, dataDir } = opts
  const edvContext = makeEdvContext({ opts })
  const authorizeWrite = makeEdvAuthorize({ opts })
  const authorizeRead = makeEdvAuthorize({ opts, expectedAction: 'read' })

  // insert a document
  fastify.post(`${routePrefix}/:edvId/documents`, {
    schema: { body: postDocumentBody },
    bodyLimit: TEN_MEGABYTES,
    preHandler: [edvContext, authorizeWrite],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const doc = request.body as IEncryptedDocument
      const { localEdvId, edvUrl } = request.edv!
      await insertDoc({ dataDir, localEdvId, doc })
      await reply
        .status(201)
        .header('location', `${edvUrl}/documents/${doc.id}`)
        .send()
    }
  })

  // update (upsert) a document
  fastify.post(`${routePrefix}/:edvId/documents/:docId`, {
    schema: { body: postDocumentBody },
    bodyLimit: TEN_MEGABYTES,
    preHandler: [edvContext, authorizeWrite],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const doc = request.body as IEncryptedDocument
      const { docId } = request.params as { docId: string }
      if (doc.id !== docId) {
        throw new DataError({
          message: 'Could not update document; ID does not match.'
        })
      }
      const { localEdvId } = request.edv!
      await updateDoc({ dataDir, localEdvId, doc })
      await reply.status(204).send()
    }
  })

  // get a document
  fastify.get(`${routePrefix}/:edvId/documents/:docId`, {
    preHandler: [edvContext, authorizeRead],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const { docId } = request.params as { docId: string }
      const { localEdvId } = request.edv!
      const doc = await getDoc({ dataDir, localEdvId, docId })
      await sendCacheableJson({ reply, obj: doc })
    }
  })

  // query for documents (both spec'd locations)
  for (const queryPath of [
    `${routePrefix}/:edvId/query`,
    `${routePrefix}/:edvId/documents/query`
  ]) {
    fastify.post(queryPath, {
      schema: { body: postDocumentQueryBody },
      // expected zcap action is `read` (default for POST is `write`)
      preHandler: [edvContext, authorizeRead],
      handler: makeQueryHandler({ opts })
    })
  }
}

function makeQueryHandler({ opts }: { opts: ResolvedEdvOptions }) {
  return async function handleQuery(
    request: FastifyRequest,
    reply: FastifyReply
  ) {
    const { dataDir } = opts
    const { localEdvId } = request.edv!
    const body = request.body as IEDVQuery
    // default `returnDocuments` to true for backwards compatibility; the
    // client sends it as a query string parameter
    const returnDocuments = !(
      (request.query as Record<string, string>).returnDocuments === 'false' ||
      body.returnDocuments === false
    )
    const { index, equals, has, count, limit } = body
    const query = { index, equals, has, limit }
    if (count) {
      await reply.send({
        count: await countDocs({ dataDir, localEdvId, query })
      })
      return
    }
    const { documents, hasMore } = await findDocs({
      dataDir,
      localEdvId,
      query
    })
    /* Note: no `cursor` value is returned to allow a search to continue
    where it left off; reference-implementation parity. */
    if (returnDocuments) {
      await reply.send({ hasMore, documents })
    } else {
      await reply.send({ hasMore, documentIds: documents.map(doc => doc.id) })
    }
  }
}
