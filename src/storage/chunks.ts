/**
 * Chunk storage: `chunks/<docId>/<chunkIndex>.json` per chunk. Chunks are
 * versioned in lockstep with their document: a chunk write is rejected
 * (409) unless `chunk.sequence` equals the document's current sequence at
 * write time.
 */
import { rm } from 'node:fs/promises'
import type { IEDVChunk } from '@interop/data-integrity-core'
import { InvalidStateError, NotFoundError } from '../errors.js'
import {
  edvLockKey,
  readJson,
  storageMutex,
  writeJsonAtomic
} from './atomic.js'
import { chunkPath, docPath } from './paths.js'

/**
 * Stores (upserts) a chunk, keyed by (vault, doc, index). The owning
 * document must exist and `chunk.sequence` must equal its current
 * sequence, else InvalidStateError (409).
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @param options.docId {string}
 * @param options.chunk {IEDVChunk}
 * @returns {Promise<void>}
 */
export async function storeChunk({
  dataDir,
  localEdvId,
  docId,
  chunk
}: {
  dataDir: string
  localEdvId: string
  docId: string
  chunk: IEDVChunk
}): Promise<void> {
  const filePath = chunkPath({
    dataDir,
    localEdvId,
    docId,
    chunkIndex: chunk.index ?? 0
  })
  await storageMutex.run(
    edvLockKey({ dataDir, localEdvId }),
    async function store() {
      const doc = (await readJson({
        filePath: docPath({ dataDir, localEdvId, docId })
      })) as { sequence: number } | null
      if (doc === null) {
        throw new NotFoundError({
          message: 'Encrypted data vault document not found.'
        })
      }
      // chunks are versioned in lockstep with the document
      if (chunk.sequence !== doc.sequence) {
        throw new InvalidStateError({
          message: 'Could not update document chunk; unexpected sequence.'
        })
      }
      await writeJsonAtomic({ filePath, value: chunk })
    }
  )
}

/**
 * Gets a chunk. Throws NotFoundError (404) if absent.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @param options.docId {string}
 * @param options.chunkIndex {string|number}
 * @returns {Promise<IEDVChunk>}
 */
export async function getChunk({
  dataDir,
  localEdvId,
  docId,
  chunkIndex
}: {
  dataDir: string
  localEdvId: string
  docId: string
  chunkIndex: string | number
}): Promise<IEDVChunk> {
  const chunk = (await readJson({
    filePath: chunkPath({ dataDir, localEdvId, docId, chunkIndex })
  })) as IEDVChunk | null
  if (chunk === null) {
    throw new NotFoundError({
      message: 'Encrypted data vault document chunk not found.'
    })
  }
  return chunk
}

/**
 * Removes a chunk.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @param options.docId {string}
 * @param options.chunkIndex {string|number}
 * @returns {Promise<boolean>} true if a chunk was removed
 */
export async function removeChunk({
  dataDir,
  localEdvId,
  docId,
  chunkIndex
}: {
  dataDir: string
  localEdvId: string
  docId: string
  chunkIndex: string | number
}): Promise<boolean> {
  const filePath = chunkPath({ dataDir, localEdvId, docId, chunkIndex })
  return storageMutex.run(
    edvLockKey({ dataDir, localEdvId }),
    async function remove() {
      try {
        await rm(filePath)
        return true
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
          return false
        }
        throw err
      }
    }
  )
}
