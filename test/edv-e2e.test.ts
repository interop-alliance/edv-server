/**
 * End-to-end tests driven by @interop/edv-client over real HTTP, with "DX
 * assertions": after each phase the expected file under the temp data dir
 * is read directly and compared against what the wire carried.
 */
import { readFile } from 'node:fs/promises'
import * as fsPath from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EdvClient } from '@interop/edv-client'
import {
  type Actor,
  createActor,
  createEdv,
  keyResolver,
  localId,
  MockHmac,
  SEEDS,
  signedRequest,
  startTestServer,
  type TestServer
} from './helpers.js'

let server: TestServer
let alice: Actor

beforeAll(async () => {
  server = await startTestServer()
  alice = await createActor({ seed: SEEDS.alice })
})

afterAll(async () => {
  await server.close()
})

function edvDirOnDisk({ edvId }: { edvId: string }): string {
  return fsPath.join(server.dataDir, 'edvs', localId({ edvId }))
}

// the vault's root zcap; sub-resource URLs are reached from it via target
// attenuation
function vaultRootZcap({ edvId }: { edvId: string }): string {
  return `urn:zcap:root:${encodeURIComponent(edvId)}`
}

async function readJsonFile(filePath: string): Promise<unknown> {
  return JSON.parse(await readFile(filePath, 'utf8'))
}

describe('vault configs', () => {
  it('creates a vault: 201 + Location, server-assigned id, file on disk', async () => {
    const hmac = await MockHmac.create()
    const config = {
      sequence: 0,
      controller: alice.did,
      // try to choose our own id; the server must ignore it
      id: `${server.edvsUrl}/z1ABxUcbcnSyMtnenFmeARhUn`,
      keyAgreementKey: {
        id: alice.keyAgreementKey.id,
        type: alice.keyAgreementKey.type
      },
      hmac: { id: hmac.id, type: hmac.type }
    }
    const response = await alice.zcapClient.write({
      url: server.edvsUrl,
      json: config
    })
    expect(response.status).toBe(201)
    const created = response.data as { id: string; sequence: number }
    expect(response.headers.get('location')).toBe(created.id)
    expect(created.id).not.toBe(config.id)
    expect(created.id.startsWith(`${server.edvsUrl}/z`)).toBe(true)
    expect(created.sequence).toBe(0)
    // DX: the config file on disk is exactly what the server returned
    const onDisk = await readJsonFile(
      fsPath.join(edvDirOnDisk({ edvId: created.id }), 'config.json')
    )
    expect(onDisk).toEqual(created)
  })

  it('accepts and ignores meterId; rejects unknown properties', async () => {
    const hmac = await MockHmac.create()
    const base = {
      sequence: 0,
      controller: alice.did,
      keyAgreementKey: {
        id: alice.keyAgreementKey.id,
        type: alice.keyAgreementKey.type
      },
      hmac: { id: hmac.id, type: hmac.type }
    }
    const response = await alice.zcapClient.write({
      url: server.edvsUrl,
      json: { ...base, meterId: 'urn:uuid:ignored' }
    })
    expect(response.status).toBe(201)

    await expect(
      alice.zcapClient.write({
        url: server.edvsUrl,
        json: { ...base, unknownProperty: true }
      })
    ).rejects.toMatchObject({ status: 400 })
  })

  it('finds a config by referenceId; [] when absent', async () => {
    const { edvId } = await createEdv({
      server,
      actor: alice,
      referenceId: 'e2e-primary'
    })
    const found = (await EdvClient.findConfig({
      url: server.edvsUrl,
      controller: alice.did,
      referenceId: 'e2e-primary',
      invocationSigner: alice.signer
    })) as { id: string } | null
    expect(found?.id).toBe(edvId)
    const missing = await EdvClient.findConfig({
      url: server.edvsUrl,
      controller: alice.did,
      referenceId: 'e2e-no-such',
      invocationSigner: alice.signer
    })
    expect(missing).toBeNull()
  })

  it('updates a config; stale sequence is a 409', async () => {
    const { client, edvId } = await createEdv({ server, actor: alice })
    const config = (await client.getConfig()) as Record<string, unknown>
    expect(config.id).toBe(edvId)
    await client.updateConfig({ config: { ...config, sequence: 1 } })
    const updated = (await client.getConfig()) as { sequence: number }
    expect(updated.sequence).toBe(1)
    // DX: disk reflects the update
    const onDisk = (await readJsonFile(
      fsPath.join(edvDirOnDisk({ edvId }), 'config.json')
    )) as { sequence: number }
    expect(onDisk.sequence).toBe(1)
    // stale sequence (replaying sequence 1) -> 409, surfaced by the
    // client as InvalidStateError
    await expect(
      client.updateConfig({ config: { ...config, sequence: 1 } })
    ).rejects.toMatchObject({ name: 'InvalidStateError' })
  })

  it('404s on a vault that does not exist', async () => {
    await expect(
      alice.zcapClient.read({
        url: `${server.edvsUrl}/z19uMCiPNET4YbcPpBcab5mEE`
      })
    ).rejects.toMatchObject({ status: 404 })
  })

  it('403s an unauthorized vault read', async () => {
    const bob = await createActor({ seed: SEEDS.bob })
    const { edvId } = await createEdv({ server, actor: alice })
    await expect(bob.zcapClient.read({ url: edvId })).rejects.toMatchObject({
      status: 403
    })
  })
})

describe('documents', () => {
  it('inserts, gets, and updates a document (with disk assertions)', async () => {
    const { client, edvId } = await createEdv({ server, actor: alice })
    const docId = await EdvClient.generateId()
    await client.insert({
      doc: { id: docId, content: { someKey: 'someValue' } },
      invocationSigner: alice.signer,
      keyResolver
    })

    // DX: the file on disk equals what the server serves over the wire
    const docUrl = `${edvId}/documents/${docId}`
    const wireDoc = (
      await signedRequest({
        url: docUrl,
        method: 'get',
        action: 'read',
        capability: vaultRootZcap({ edvId }),
        signer: alice.signer
      })
    ).data as Record<string, unknown>
    const diskDoc = await readJsonFile(
      fsPath.join(edvDirOnDisk({ edvId }), 'docs', `${docId}.json`)
    )
    expect(diskDoc).toEqual(wireDoc)
    expect(wireDoc.sequence).toBe(0)
    expect((wireDoc.jwe as { ciphertext: string }).ciphertext).toBeTypeOf(
      'string'
    )

    // decrypted read through the client
    const decrypted = (await client.get({ id: docId })) as {
      content: object
      sequence: number
    }
    expect(decrypted.content).toEqual({ someKey: 'someValue' })

    // update
    await client.update({
      doc: { ...decrypted, content: { someKey: 'updatedValue' } },
      invocationSigner: alice.signer,
      keyResolver
    })
    const updated = (await client.get({ id: docId })) as {
      content: object
      sequence: number
    }
    expect(updated.sequence).toBe(1)
    expect(updated.content).toEqual({ someKey: 'updatedValue' })
  })

  it('409s a duplicate insert', async () => {
    const { client } = await createEdv({ server, actor: alice })
    const docId = await EdvClient.generateId()
    const doc = { id: docId, content: { someKey: 'someValue' } }
    await client.insert({ doc, invocationSigner: alice.signer, keyResolver })
    await expect(
      client.insert({ doc, invocationSigner: alice.signer, keyResolver })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
  })

  it('409s a stale-sequence update', async () => {
    const { client } = await createEdv({ server, actor: alice })
    const docId = await EdvClient.generateId()
    await client.insert({
      doc: { id: docId, content: { v: '1' } },
      invocationSigner: alice.signer,
      keyResolver
    })
    const version1 = await client.get({ id: docId })
    await client.update({
      doc: version1,
      invocationSigner: alice.signer,
      keyResolver
    })
    // updating from the same base version again replays sequence 1
    await expect(
      client.update({
        doc: version1,
        invocationSigner: alice.signer,
        keyResolver
      })
    ).rejects.toMatchObject({ name: 'InvalidStateError' })
  })

  it('409s a unique-attribute conflict', async () => {
    const { client } = await createEdv({ server, actor: alice })
    client.ensureIndex({ attribute: 'content.uniqueKey', unique: true })
    await client.insert({
      doc: {
        id: await EdvClient.generateId(),
        content: { uniqueKey: 'taken' }
      },
      invocationSigner: alice.signer,
      keyResolver
    })
    await expect(
      client.insert({
        doc: {
          id: await EdvClient.generateId(),
          content: { uniqueKey: 'taken' }
        },
        invocationSigner: alice.signer,
        keyResolver
      })
    ).rejects.toMatchObject({ name: 'DuplicateError' })
  })

  it('400s when body id does not match the URL doc id', async () => {
    const { client, edvId } = await createEdv({ server, actor: alice })
    const docId = await EdvClient.generateId()
    await client.insert({
      doc: { id: docId, content: { someKey: 'x' } },
      invocationSigner: alice.signer,
      keyResolver
    })
    const wireDoc = (
      await signedRequest({
        url: `${edvId}/documents/${docId}`,
        method: 'get',
        action: 'read',
        capability: vaultRootZcap({ edvId }),
        signer: alice.signer
      })
    ).data as object
    const otherDocId = await EdvClient.generateId()
    await expect(
      signedRequest({
        url: `${edvId}/documents/${otherDocId}`,
        method: 'post',
        action: 'write',
        json: wireDoc,
        capability: vaultRootZcap({ edvId }),
        signer: alice.signer
      })
    ).rejects.toMatchObject({ status: 400 })
  })
})

describe('queries', () => {
  let client: EdvClient

  beforeAll(async () => {
    ;({ client } = await createEdv({ server, actor: alice }))
    client.ensureIndex({ attribute: 'content.country' })
    client.ensureIndex({ attribute: 'content.color' })
    for (const content of [
      { country: 'france', color: 'blue' },
      { country: 'france', color: 'red' },
      { country: 'spain', color: 'blue' }
    ]) {
      await client.insert({
        doc: { id: await EdvClient.generateId(), content },
        invocationSigner: alice.signer,
        keyResolver
      })
    }
  })

  it('queries by equals', async () => {
    const { documents } = (await client.find({
      equals: { 'content.country': 'france' }
    })) as { documents: Array<{ content: { color: string } }> }
    expect(documents).toHaveLength(2)
    expect(documents.map(doc => doc.content.color).sort()).toEqual([
      'blue',
      'red'
    ])
  })

  it('queries by equals with AND pairs', async () => {
    const { documents } = (await client.find({
      equals: { 'content.country': 'france', 'content.color': 'blue' }
    })) as { documents: unknown[] }
    expect(documents).toHaveLength(1)
  })

  it('queries by has', async () => {
    const { documents } = (await client.find({
      has: 'content.color'
    })) as { documents: unknown[] }
    expect(documents).toHaveLength(3)
  })

  it('counts', async () => {
    const count = await client.count({
      equals: { 'content.country': 'france' }
    })
    expect(count).toBe(2)
  })

  it('applies limit and reports hasMore', async () => {
    const { documents, hasMore } = (await client.find({
      equals: { 'content.country': 'france' },
      limit: 1
    })) as { documents: unknown[]; hasMore: boolean }
    expect(documents).toHaveLength(1)
    expect(hasMore).toBe(true)
    const all = (await client.find({
      equals: { 'content.country': 'france' },
      limit: 5
    })) as { documents: unknown[]; hasMore: boolean }
    expect(all.documents).toHaveLength(2)
    expect(all.hasMore).toBe(false)
  })

  it('returns documentIds when returnDocuments=false', async () => {
    const result = (await client.find({
      equals: { 'content.country': 'france' },
      returnDocuments: false
    })) as { documentIds?: string[]; documents?: unknown[] }
    expect(result.documents).toBeUndefined()
    expect(result.documentIds).toHaveLength(2)
  })
})

describe('streams (chunks)', () => {
  it('stores chunks via insert-with-stream; lockstep + delete semantics', async () => {
    const { client, edvId } = await createEdv({ server, actor: alice })
    const docId = await EdvClient.generateId()
    const data = new Uint8Array(50).map((_, i) => i)
    const stream = new ReadableStream({
      pull(controller) {
        controller.enqueue(data)
        controller.close()
      }
    })
    const inserted = (await client.insert({
      doc: { id: docId, content: { someKey: 'streamed' } },
      stream,
      invocationSigner: alice.signer,
      keyResolver
    })) as { sequence: number; stream: { chunks: number } }
    // streams are written in an update after the initial document write
    expect(inserted.sequence).toBe(1)
    expect(inserted.stream.chunks).toBe(1)

    // DX: the chunk file is on disk, verbatim with the wire
    const chunkUrl = `${edvId}/documents/${docId}/chunks/0`
    const capability = vaultRootZcap({ edvId })
    const wireChunk = (
      await signedRequest({
        url: chunkUrl,
        method: 'get',
        action: 'read',
        capability,
        signer: alice.signer
      })
    ).data as { sequence: number }
    const diskChunk = await readJsonFile(
      fsPath.join(edvDirOnDisk({ edvId }), 'chunks', docId, '0.json')
    )
    expect(diskChunk).toEqual(wireChunk)
    // the chunk was written while the doc was at sequence 0; the stream
    // metadata update bumped the doc to 1 afterwards
    expect(wireChunk.sequence).toBe(0)

    // doc/chunk lockstep: writing a chunk with a stale sequence is a 409
    await expect(
      signedRequest({
        url: chunkUrl,
        method: 'post',
        action: 'write',
        json: { ...wireChunk, sequence: 99 },
        capability,
        signer: alice.signer
      })
    ).rejects.toMatchObject({ status: 409 })

    // delete chunk -> 204; get -> 404; delete again -> 404
    const deleteResponse = await signedRequest({
      url: chunkUrl,
      method: 'delete',
      action: 'write',
      capability,
      signer: alice.signer
    })
    expect(deleteResponse.status).toBe(204)
    await expect(
      signedRequest({
        url: chunkUrl,
        method: 'get',
        action: 'read',
        capability,
        signer: alice.signer
      })
    ).rejects.toMatchObject({ status: 404 })
    await expect(
      signedRequest({
        url: chunkUrl,
        method: 'delete',
        action: 'write',
        capability,
        signer: alice.signer
      })
    ).rejects.toMatchObject({ status: 404 })
  })
})
