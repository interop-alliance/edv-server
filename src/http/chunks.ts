/**
 * Chunk routes: store, get, delete. Chunks are upserts keyed by
 * (vault, doc, index) and are versioned in lockstep with their document.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { IEDVChunk } from '@interop/data-integrity-core'
import type { ResolvedEdvOptions } from '../config.js'
import { sendCacheableJson } from '../helpers.js'
import { postChunkBody } from '../schemas.js'
import { getChunk, removeChunk, storeChunk } from '../storage/chunks.js'
import { makeEdvAuthorize, makeEdvContext } from './edv-context.js'

const TEN_MEGABYTES = 10 * 1024 * 1024

export function registerChunkRoutes({
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
  const chunkPath = `${routePrefix}/:edvId/documents/:docId/chunks/:chunkIndex`

  // store a chunk
  fastify.post(chunkPath, {
    schema: { body: postChunkBody },
    bodyLimit: TEN_MEGABYTES,
    preHandler: [edvContext, authorizeWrite],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const { docId } = request.params as { docId: string }
      const { localEdvId } = request.edv!
      await storeChunk({
        dataDir,
        localEdvId,
        docId,
        chunk: request.body as IEDVChunk
      })
      await reply.status(204).send()
    }
  })

  // get a chunk
  fastify.get(chunkPath, {
    preHandler: [edvContext, authorizeRead],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const { docId, chunkIndex } = request.params as {
        docId: string
        chunkIndex: string
      }
      const { localEdvId } = request.edv!
      const chunk = await getChunk({ dataDir, localEdvId, docId, chunkIndex })
      await sendCacheableJson({ reply, obj: chunk })
    }
  })

  // delete a chunk
  fastify.delete(chunkPath, {
    preHandler: [edvContext, authorizeWrite],
    async handler(request: FastifyRequest, reply: FastifyReply) {
      const { docId, chunkIndex } = request.params as {
        docId: string
        chunkIndex: string
      }
      const { localEdvId } = request.edv!
      const removed = await removeChunk({
        dataDir,
        localEdvId,
        docId,
        chunkIndex
      })
      await reply.status(removed ? 204 : 404).send()
    }
  })
}
