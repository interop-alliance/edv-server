/**
 * Document storage: one pretty-printed JSON file per document under
 * `docs/`. All writes run under the vault mutex; invariants (duplicate
 * insert, sequence previous + 1 on update, unique blinded attributes) are
 * enforced inside the lock.
 */
import type { IEncryptedDocument } from '@interop/data-integrity-core'
import { DuplicateError, InvalidStateError, NotFoundError } from '../errors.js'
import { validateDocSequence } from '../helpers.js'
import {
  edvLockKey,
  readJson,
  storageMutex,
  writeJsonAtomic
} from './atomic.js'
import { docPath } from './paths.js'
import { findUniqueConflict } from './query.js'

/**
 * Inserts a document. Fails with DuplicateError (409) if a document with
 * the same ID exists, or if a `unique: true` blinded attribute is already
 * claimed by another document in the vault. Inserting with a non-zero
 * sequence is allowed (eases copying docs between EDVs).
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @param options.doc {IEncryptedDocument}
 * @returns {Promise<IEncryptedDocument>}
 */
export async function insertDoc({
  dataDir,
  localEdvId,
  doc
}: {
  dataDir: string
  localEdvId: string
  doc: IEncryptedDocument
}): Promise<IEncryptedDocument> {
  validateDocSequence({ sequence: doc.sequence })
  const filePath = docPath({ dataDir, localEdvId, docId: doc.id })
  return storageMutex.run(
    edvLockKey({ dataDir, localEdvId }),
    async function insert() {
      const existing = await readJson({ filePath })
      if (existing !== null) {
        throw new DuplicateError({
          message: 'Duplicate document.'
        })
      }
      await _assertNoUniqueConflict({ dataDir, localEdvId, doc })
      await writeJsonAtomic({ filePath, value: doc })
      return doc
    }
  )
}

/**
 * Updates (upserts) a document. When the document exists, the incoming
 * sequence must be exactly previous + 1, else InvalidStateError (409).
 * When it does not exist, the update inserts it.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @param options.doc {IEncryptedDocument}
 * @returns {Promise<IEncryptedDocument>}
 */
export async function updateDoc({
  dataDir,
  localEdvId,
  doc
}: {
  dataDir: string
  localEdvId: string
  doc: IEncryptedDocument
}): Promise<IEncryptedDocument> {
  validateDocSequence({ sequence: doc.sequence })
  const filePath = docPath({ dataDir, localEdvId, docId: doc.id })
  return storageMutex.run(
    edvLockKey({ dataDir, localEdvId }),
    async function update() {
      const existing = (await readJson({
        filePath
      })) as IEncryptedDocument | null
      if (existing !== null && doc.sequence !== existing.sequence + 1) {
        throw new InvalidStateError({
          message: 'Could not update document; unexpected sequence.'
        })
      }
      await _assertNoUniqueConflict({ dataDir, localEdvId, doc })
      await writeJsonAtomic({ filePath, value: doc })
      return doc
    }
  )
}

/**
 * Gets a document by ID. Throws NotFoundError (404) if absent.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @param options.docId {string}
 * @returns {Promise<IEncryptedDocument>}
 */
export async function getDoc({
  dataDir,
  localEdvId,
  docId
}: {
  dataDir: string
  localEdvId: string
  docId: string
}): Promise<IEncryptedDocument> {
  const doc = (await readJson({
    filePath: docPath({ dataDir, localEdvId, docId })
  })) as IEncryptedDocument | null
  if (doc === null) {
    throw new NotFoundError({
      message: 'Encrypted data vault document not found.'
    })
  }
  return doc
}

async function _assertNoUniqueConflict({
  dataDir,
  localEdvId,
  doc
}: {
  dataDir: string
  localEdvId: string
  doc: IEncryptedDocument
}): Promise<void> {
  const conflictingDocId = await findUniqueConflict({
    dataDir,
    localEdvId,
    doc
  })
  if (conflictingDocId !== null) {
    throw new DuplicateError({
      message: 'Could not write document; a unique attribute is already in use.'
    })
  }
}
