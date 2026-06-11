import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import * as path from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type {
  IEDVConfig,
  IEncryptedDocument
} from '@interop/data-integrity-core'
import { generateLocalId } from '../src/helpers.js'
import {
  findConfigs,
  getConfig,
  insertConfig,
  updateConfig
} from '../src/storage/edvs.js'
import { getDoc, insertDoc, updateDoc } from '../src/storage/docs.js'
import { getChunk, removeChunk, storeChunk } from '../src/storage/chunks.js'
import { configPath, docPath } from '../src/storage/paths.js'

const BASE = 'https://edv.example/edvs'

let dataDir: string

beforeAll(async () => {
  dataDir = await mkdtemp(path.join(tmpdir(), 'edv-storage-test-'))
})

afterAll(async () => {
  await rm(dataDir, { recursive: true, force: true })
})

function mockJwe() {
  return {
    protected: 'eyJlbmMiOiJYQzIwUCJ9',
    recipients: [
      {
        header: { alg: 'ECDH-ES+A256KW', kid: 'urn:kak:1' },
        encrypted_key: 'OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug'
      }
    ],
    iv: 'i8Nins2vTI3PlrYW',
    ciphertext: 'Cb-963UCXblINT8F6MDHzMJN9EAhK3I',
    tag: 'pfZO0JulJcrc3trOZy8rjA'
  }
}

async function makeConfig({
  referenceId
}: { referenceId?: string } = {}): Promise<IEDVConfig> {
  const localId = await generateLocalId()
  const config: IEDVConfig = {
    id: `${BASE}/${localId}`,
    controller: 'did:key:z6MkExample',
    sequence: 0,
    keyAgreementKey: { id: 'urn:kak:1', type: 'X25519KeyAgreementKey2020' },
    hmac: { id: 'urn:hmac:1', type: 'Sha256HmacKey2019' }
  }
  if (referenceId !== undefined) {
    config.referenceId = referenceId
  }
  return config
}

function makeDoc({
  id,
  sequence = 0,
  indexed
}: {
  id: string
  sequence?: number
  indexed?: IEncryptedDocument['indexed']
}): IEncryptedDocument {
  return { id, sequence, jwe: mockJwe(), indexed: indexed ?? [] }
}

describe('storage/edvs', () => {
  it('inserts and reads back a config, verbatim on disk', async () => {
    const config = await makeConfig()
    await insertConfig({ dataDir, config })
    const localEdvId = config.id!.split('/').pop()!
    const read = await getConfig({ dataDir, localEdvId })
    expect(read).toEqual(config)
    // the file on disk is the config verbatim, pretty-printed
    const onDisk = JSON.parse(
      await readFile(configPath({ dataDir, localEdvId }), 'utf8')
    )
    expect(onDisk).toEqual(config)
  })

  it('404s on a missing vault', async () => {
    const missingId = await generateLocalId()
    await expect(
      getConfig({ dataDir, localEdvId: missingId })
    ).rejects.toMatchObject({ name: 'NotFoundError', httpStatusCode: 404 })
  })

  it('enforces (controller, referenceId) uniqueness', async () => {
    const first = await makeConfig({ referenceId: 'primary-unique' })
    await insertConfig({ dataDir, config: first })
    const duplicate = await makeConfig({ referenceId: 'primary-unique' })
    await expect(
      insertConfig({ dataDir, config: duplicate })
    ).rejects.toMatchObject({ name: 'DuplicateError', httpStatusCode: 409 })
  })

  it('finds a config by controller + referenceId', async () => {
    const config = await makeConfig({ referenceId: 'findable' })
    await insertConfig({ dataDir, config })
    const found = await findConfigs({
      dataDir,
      controller: config.controller,
      referenceId: 'findable'
    })
    expect(found).toEqual([config])
    const none = await findConfigs({
      dataDir,
      controller: config.controller,
      referenceId: 'no-such-reference'
    })
    expect(none).toEqual([])
  })

  it('updates a config only with sequence previous + 1', async () => {
    const config = await makeConfig()
    await insertConfig({ dataDir, config })
    const stale = { ...config, sequence: 5 }
    await expect(
      updateConfig({ dataDir, config: stale })
    ).rejects.toMatchObject({ name: 'InvalidStateError', httpStatusCode: 409 })
    const next = { ...config, sequence: 1 }
    await updateConfig({ dataDir, config: next })
    const localEdvId = config.id!.split('/').pop()!
    expect((await getConfig({ dataDir, localEdvId })).sequence).toBe(1)
  })
})

describe('storage/docs', () => {
  let localEdvId: string

  beforeAll(async () => {
    const config = await makeConfig()
    await insertConfig({ dataDir, config })
    localEdvId = config.id!.split('/').pop()!
  })

  it('inserts and reads back a document, verbatim on disk', async () => {
    const doc = makeDoc({ id: await generateLocalId() })
    await insertDoc({ dataDir, localEdvId, doc })
    const read = await getDoc({ dataDir, localEdvId, docId: doc.id })
    expect(read).toEqual(doc)
    const onDisk = JSON.parse(
      await readFile(docPath({ dataDir, localEdvId, docId: doc.id }), 'utf8')
    )
    expect(onDisk).toEqual(doc)
  })

  it('409s on duplicate insert', async () => {
    const doc = makeDoc({ id: await generateLocalId() })
    await insertDoc({ dataDir, localEdvId, doc })
    await expect(insertDoc({ dataDir, localEdvId, doc })).rejects.toMatchObject(
      { name: 'DuplicateError', httpStatusCode: 409 }
    )
  })

  it('allows insert with non-zero sequence', async () => {
    const doc = makeDoc({ id: await generateLocalId(), sequence: 7 })
    await insertDoc({ dataDir, localEdvId, doc })
    expect(
      (await getDoc({ dataDir, localEdvId, docId: doc.id })).sequence
    ).toBe(7)
  })

  it('updates only with sequence previous + 1, and upserts', async () => {
    const doc = makeDoc({ id: await generateLocalId() })
    await insertDoc({ dataDir, localEdvId, doc })
    await expect(
      updateDoc({ dataDir, localEdvId, doc: { ...doc, sequence: 2 } })
    ).rejects.toMatchObject({
      name: 'InvalidStateError',
      httpStatusCode: 409
    })
    await updateDoc({ dataDir, localEdvId, doc: { ...doc, sequence: 1 } })
    expect(
      (await getDoc({ dataDir, localEdvId, docId: doc.id })).sequence
    ).toBe(1)
    // upsert: updating a nonexistent doc inserts it
    const fresh = makeDoc({ id: await generateLocalId(), sequence: 0 })
    await updateDoc({ dataDir, localEdvId, doc: fresh })
    expect(await getDoc({ dataDir, localEdvId, docId: fresh.id })).toEqual(
      fresh
    )
  })

  it('rejects invalid document IDs before touching the filesystem', async () => {
    const doc = makeDoc({ id: 'not-a-valid-id' })
    await expect(insertDoc({ dataDir, localEdvId, doc })).rejects.toMatchObject(
      { httpStatusCode: 400 }
    )
  })

  it('enforces unique blinded attributes across documents', async () => {
    const indexed = [
      {
        hmac: { id: 'urn:hmac:1', type: 'Sha256HmacKey2019' },
        sequence: 0,
        attributes: [{ name: 'bName', value: 'bValue', unique: true }]
      }
    ]
    const first = makeDoc({ id: await generateLocalId(), indexed })
    await insertDoc({ dataDir, localEdvId, doc: first })
    const second = makeDoc({ id: await generateLocalId(), indexed })
    await expect(
      insertDoc({ dataDir, localEdvId, doc: second })
    ).rejects.toMatchObject({ name: 'DuplicateError', httpStatusCode: 409 })
    // same attribute without `unique` is fine
    const nonUnique = makeDoc({
      id: await generateLocalId(),
      indexed: [
        {
          hmac: { id: 'urn:hmac:1', type: 'Sha256HmacKey2019' },
          sequence: 0,
          attributes: [{ name: 'bName', value: 'bValue' }]
        }
      ]
    })
    await insertDoc({ dataDir, localEdvId, doc: nonUnique })
    // updating the original doc keeps its own unique attribute (no
    // self-conflict)
    await updateDoc({ dataDir, localEdvId, doc: { ...first, sequence: 1 } })
  })
})

describe('storage/chunks', () => {
  let localEdvId: string
  let docId: string

  beforeAll(async () => {
    const config = await makeConfig()
    await insertConfig({ dataDir, config })
    localEdvId = config.id!.split('/').pop()!
    docId = await generateLocalId()
    await insertDoc({
      dataDir,
      localEdvId,
      doc: makeDoc({ id: docId, sequence: 0 })
    })
  })

  it('stores and gets a chunk in lockstep with the doc sequence', async () => {
    const chunk = { sequence: 0, index: 0, offset: 0, jwe: mockJwe() }
    await storeChunk({ dataDir, localEdvId, docId, chunk })
    const read = await getChunk({ dataDir, localEdvId, docId, chunkIndex: 0 })
    expect(read).toEqual(chunk)
  })

  it('409s when chunk.sequence does not match doc.sequence', async () => {
    const chunk = { sequence: 3, index: 1, offset: 0, jwe: mockJwe() }
    await expect(
      storeChunk({ dataDir, localEdvId, docId, chunk })
    ).rejects.toMatchObject({
      name: 'InvalidStateError',
      httpStatusCode: 409
    })
  })

  it('404s storing a chunk for a missing doc', async () => {
    const chunk = { sequence: 0, index: 0, offset: 0, jwe: mockJwe() }
    await expect(
      storeChunk({
        dataDir,
        localEdvId,
        docId: await generateLocalId(),
        chunk
      })
    ).rejects.toMatchObject({ name: 'NotFoundError', httpStatusCode: 404 })
  })

  it('removes a chunk; second removal reports false', async () => {
    const chunk = { sequence: 0, index: 2, offset: 0, jwe: mockJwe() }
    await storeChunk({ dataDir, localEdvId, docId, chunk })
    expect(
      await removeChunk({ dataDir, localEdvId, docId, chunkIndex: 2 })
    ).toBe(true)
    expect(
      await removeChunk({ dataDir, localEdvId, docId, chunkIndex: 2 })
    ).toBe(false)
    await expect(
      getChunk({ dataDir, localEdvId, docId, chunkIndex: 2 })
    ).rejects.toMatchObject({ name: 'NotFoundError', httpStatusCode: 404 })
  })

  it('404s on an invalid chunk index', async () => {
    await expect(
      getChunk({ dataDir, localEdvId, docId, chunkIndex: '../evil' })
    ).rejects.toMatchObject({ name: 'NotFoundError', httpStatusCode: 404 })
  })
})
