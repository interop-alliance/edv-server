/**
 * On-disk path builders. Every ID is validated before being used as a path
 * segment (`assert128BitId` for vault/doc IDs, `/^\d+$/` for chunk indexes,
 * sha256 hex for revocation file names), so all paths are filesystem-safe by
 * construction.
 *
 * Layout:
 * ```
 * <dataDir>/edvs/<localEdvId>/
 *   config.json                       IEDVConfig verbatim
 *   docs/<docId>.json                 IEncryptedDocument verbatim
 *   chunks/<docId>/<chunkIndex>.json  IEDVChunk verbatim
 *   revocations/<sha256hex(zcapId)>.json
 * ```
 */
import { createHash } from 'node:crypto'
import * as path from 'node:path'
import { assert128BitId } from '../helpers.js'
import { NotFoundError } from '../errors.js'

export function edvsDir({ dataDir }: { dataDir: string }): string {
  return path.join(dataDir, 'edvs')
}

export function edvDir({
  dataDir,
  localEdvId
}: {
  dataDir: string
  localEdvId: string
}): string {
  assert128BitId({ id: localEdvId })
  return path.join(edvsDir({ dataDir }), localEdvId)
}

export function configPath({
  dataDir,
  localEdvId
}: {
  dataDir: string
  localEdvId: string
}): string {
  return path.join(edvDir({ dataDir, localEdvId }), 'config.json')
}

export function docsDir({
  dataDir,
  localEdvId
}: {
  dataDir: string
  localEdvId: string
}): string {
  return path.join(edvDir({ dataDir, localEdvId }), 'docs')
}

export function docPath({
  dataDir,
  localEdvId,
  docId
}: {
  dataDir: string
  localEdvId: string
  docId: string
}): string {
  assert128BitId({ id: docId })
  return path.join(docsDir({ dataDir, localEdvId }), `${docId}.json`)
}

/**
 * Asserts that a chunk index path/parameter segment is a plain non-negative
 * decimal integer string. Throws 404 (mirroring bedrock, which reports an
 * unparseable chunk index as "chunk not found").
 *
 * @param options {object}
 * @param options.chunkIndex {string|number}   the chunk index to validate
 * @returns {number} the parsed chunk index
 */
export function assertChunkIndex({
  chunkIndex
}: {
  chunkIndex: string | number
}): number {
  const text = String(chunkIndex)
  if (!/^\d+$/.test(text)) {
    throw new NotFoundError({
      message: 'Encrypted data vault document chunk not found.'
    })
  }
  return parseInt(text, 10)
}

export function chunksDirForDoc({
  dataDir,
  localEdvId,
  docId
}: {
  dataDir: string
  localEdvId: string
  docId: string
}): string {
  assert128BitId({ id: docId })
  return path.join(edvDir({ dataDir, localEdvId }), 'chunks', docId)
}

export function chunkPath({
  dataDir,
  localEdvId,
  docId,
  chunkIndex
}: {
  dataDir: string
  localEdvId: string
  docId: string
  chunkIndex: string | number
}): string {
  const index = assertChunkIndex({ chunkIndex })
  return path.join(
    chunksDirForDoc({ dataDir, localEdvId, docId }),
    `${index}.json`
  )
}

export function revocationsDir({
  dataDir,
  localEdvId
}: {
  dataDir: string
  localEdvId: string
}): string {
  return path.join(edvDir({ dataDir, localEdvId }), 'revocations')
}

export function revocationPath({
  dataDir,
  localEdvId,
  capabilityId
}: {
  dataDir: string
  localEdvId: string
  capabilityId: string
}): string {
  const hash = createHash('sha256').update(capabilityId, 'utf8').digest('hex')
  return path.join(revocationsDir({ dataDir, localEdvId }), `${hash}.json`)
}

/**
 * Extracts the local EDV ID from a full EDV URL (`<base>/<localId>`).
 *
 * @param options {object}
 * @param options.id {string}   the full EDV ID URL
 * @returns {string} the local (base58 multibase) vault ID
 */
export function parseLocalId({ id }: { id: string }): string {
  const localId = id.slice(id.lastIndexOf('/') + 1)
  assert128BitId({ id: localId })
  return localId
}
