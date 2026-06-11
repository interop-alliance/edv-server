/**
 * Wire-level server behavior: error shapes, unsigned requests, validation,
 * ETag revalidation, and CORS.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EdvClient } from '@interop/edv-client'
import {
  type Actor,
  createActor,
  createEdv,
  keyResolver,
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

describe('server basics', () => {
  it('rejects an unsigned create request', async () => {
    const response = await fetch(server.edvsUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        sequence: 0,
        controller: 'did:key:z6MkUnsigned',
        keyAgreementKey: { id: 'urn:kak', type: 'X25519KeyAgreementKey2020' },
        hmac: { id: 'urn:hmac', type: 'Sha256HmacKey2019' }
      })
    })
    expect([400, 403]).toContain(response.status)
  })

  it('400s an invalid config body with a {name, message} error shape', async () => {
    const response = await fetch(server.edvsUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sequence: 0 })
    })
    expect(response.status).toBe(400)
    const body = (await response.json()) as { name: string; message: string }
    expect(body.name).toBeTypeOf('string')
    expect(body.message).toBeTypeOf('string')
  })

  it('400s a malformed vault id', async () => {
    await expect(
      signedRequest({
        url: `${server.edvsUrl}/not-a-valid-id`,
        method: 'get',
        action: 'read',
        capability: `urn:zcap:root:${encodeURIComponent(
          `${server.edvsUrl}/not-a-valid-id`
        )}`,
        signer: alice.signer
      })
    ).rejects.toMatchObject({ status: 400 })
  })

  it('serves documents with an ETag and revalidates with 304', async () => {
    const { client, edvId } = await createEdv({ server, actor: alice })
    const docId = await EdvClient.generateId()
    await client.insert({
      doc: { id: docId, content: { someKey: 'etag-test' } },
      invocationSigner: alice.signer,
      keyResolver
    })
    const docUrl = `${edvId}/documents/${docId}`
    const capability = `urn:zcap:root:${encodeURIComponent(edvId)}`
    const first = await signedRequest({
      url: docUrl,
      method: 'get',
      action: 'read',
      capability,
      signer: alice.signer
    })
    expect(first.status).toBe(200)
    const etagValue = first.headers.get('etag')
    expect(etagValue).toBeTruthy()
    expect(first.headers.get('cache-control')).toBe('private, no-cache')

    // revalidation with the etag yields 304 Not Modified (the http
    // client treats any non-2xx as an error)
    await expect(
      signedRequest({
        url: docUrl,
        method: 'get',
        action: 'read',
        capability,
        signer: alice.signer,
        headers: { 'if-none-match': etagValue! }
      })
    ).rejects.toMatchObject({ status: 304 })
  })

  it('answers CORS preflight on the create endpoint', async () => {
    const response = await fetch(server.edvsUrl, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://app.example',
        'access-control-request-method': 'POST',
        'access-control-request-headers':
          'authorization,capability-invocation,content-type,digest'
      }
    })
    expect(response.status).toBeLessThan(300)
    expect(response.headers.get('access-control-allow-origin')).toBeTruthy()
    expect(response.headers.get('access-control-max-age')).toBe('86400')
  })

  it('enforces the expected action (write zcap action cannot read)', async () => {
    const { edvId } = await createEdv({ server, actor: alice })
    // sign a GET but with capabilityAction 'write': the server expects
    // 'read' for GETs and must refuse
    await expect(
      signedRequest({
        url: edvId,
        method: 'get',
        action: 'write',
        capability: `urn:zcap:root:${encodeURIComponent(edvId)}`,
        signer: alice.signer
      })
    ).rejects.toMatchObject({ status: 403 })
  })
})
