/**
 * e2e test fixtures: seeded did:key actors (alice, bob), mock client-side
 * crypto (X25519 KAK derived from the actor's Ed25519 key, a SHA-256 HMAC
 * for attribute blinding, and a key resolver), plus a temp-dir + ephemeral
 * port server fixture.
 */
import { createServer } from 'node:net'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import * as path from 'node:path'
import type { FastifyInstance } from 'fastify'
import * as didKey from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import { ZcapClient } from '@interop/ezcap'
import { EdvClient } from '@interop/edv-client'
import { signCapabilityInvocation } from '@interop/http-signature-zcap-invoke'
import { DEFAULT_HEADERS, httpClient } from '@interop/http-client'
import type { ISigner, IZcap } from '@interop/data-integrity-core'
import { createApp } from '../src/index.js'

const didKeyDriver = didKey.driver()
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey.from,
  // derive X25519 keyAgreement keys from Ed25519 keys so resolved did:key
  // documents include a keyAgreement method
  enableEncryptionKeyDerivation: true
})

/** Deterministic test seeds (32 bytes each). */
export const SEEDS = {
  alice: new Uint8Array(32).fill(1),
  bob: new Uint8Array(32).fill(2)
}

export interface Actor {
  did: string
  signer: ISigner
  keyAgreementKey: X25519KeyAgreementKey2020
  zcapClient: ZcapClient
}

/** Map-backed public key store for the client-side keyResolver. */
export const keyStorage = new Map<string, object>()

export function keyResolver({ id }: { id: string }): object {
  const key = keyStorage.get(id)
  if (key) {
    return key
  }
  throw new Error(`Key ${id} not found`)
}

/**
 * Creates a did:key actor from a seed: capability invocation signer, a
 * matching X25519 key agreement key (registered with the keyResolver), and
 * a ZcapClient.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}
 * @returns {Promise<Actor>}
 */
export async function createActor({
  seed
}: {
  seed: Uint8Array
}): Promise<Actor> {
  const verificationKeyPair = await Ed25519VerificationKey.generate({ seed })
  const { methodFor } = await didKeyDriver.fromKeyPair({
    verificationKeyPair
  })
  const invocationMethod = methodFor({ purpose: 'capabilityInvocation' }) as {
    id: string
    controller: string
  }
  const signer = verificationKeyPair.signer() as ISigner
  signer.id = invocationMethod.id

  const keyAgreementMethod = methodFor({ purpose: 'keyAgreement' }) as {
    id: string
    controller: string
  }
  const keyAgreementKey =
    X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
      keyPair: verificationKeyPair
    })
  keyAgreementKey.id = keyAgreementMethod.id
  keyAgreementKey.controller = keyAgreementMethod.controller
  keyStorage.set(
    keyAgreementKey.id,
    keyAgreementKey.export({ publicKey: true, includeContext: true })
  )

  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: signer,
    delegationSigner: signer
  })

  return {
    did: invocationMethod.controller,
    signer,
    keyAgreementKey,
    zcapClient
  }
}

/**
 * Minimal SHA-256 HMAC for blinding indexed attributes (the server never
 * sees the key). Ported from the edv-client test mocks.
 */
export class MockHmac {
  id = 'urn:mockhmac:1'
  type = 'Sha256HmacKey2019'
  algorithm = 'HS256'
  private key: CryptoKey

  private constructor({ key }: { key: CryptoKey }) {
    this.key = key
  }

  static async create(): Promise<MockHmac> {
    const data = Buffer.from(
      '49JUNpuy7808NoTTbB0q8rgRuPSMyeqSswCnWKr0MF4',
      'base64url'
    )
    const key = await crypto.subtle.importKey(
      'raw',
      data,
      { name: 'HMAC', hash: { name: 'SHA-256' } },
      true,
      ['sign', 'verify']
    )
    return new MockHmac({ key })
  }

  async sign({ data }: { data: Uint8Array }): Promise<string> {
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        'HMAC',
        this.key,
        data as Uint8Array<ArrayBuffer>
      )
    )
    return Buffer.from(signature).toString('base64url')
  }

  async verify({
    data,
    signature
  }: {
    data: Uint8Array
    signature: string
  }): Promise<boolean> {
    return crypto.subtle.verify(
      'HMAC',
      this.key,
      Buffer.from(signature, 'base64url'),
      data as Uint8Array<ArrayBuffer>
    )
  }
}

export interface TestServer {
  app: FastifyInstance
  baseUrl: string
  edvsUrl: string
  dataDir: string
  close: () => Promise<void>
}

async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address === 'string') {
        reject(new Error('Could not allocate a port.'))
        return
      }
      server.close(() => resolve(address.port))
    })
  })
}

/**
 * Starts an EDV server on an ephemeral port with a fresh temp data dir.
 *
 * @returns {Promise<TestServer>}
 */
export async function startTestServer(): Promise<TestServer> {
  const dataDir = await mkdtemp(path.join(tmpdir(), 'edv-server-e2e-'))
  const port = await getFreePort()
  const baseUrl = `http://localhost:${port}`
  const app = createApp({ baseUrl, dataDir })
  await app.listen({ port, host: '127.0.0.1' })
  return {
    app,
    baseUrl,
    edvsUrl: `${baseUrl}/edvs`,
    dataDir,
    async close() {
      await app.close()
      await rm(dataDir, { recursive: true, force: true })
    }
  }
}

/**
 * Creates a vault for the actor (signed createEdv) and returns an
 * EdvClient bound to it.
 *
 * @param options {object}
 * @param options.server {TestServer}
 * @param options.actor {Actor}
 * @param [options.referenceId] {string}
 * @returns {Promise<{client: EdvClient, edvId: string, hmac: MockHmac}>}
 */
export async function createEdv({
  server,
  actor,
  referenceId
}: {
  server: TestServer
  actor: Actor
  referenceId?: string
}): Promise<{ client: EdvClient; edvId: string; hmac: MockHmac }> {
  const hmac = await MockHmac.create()
  const config: Record<string, unknown> = {
    sequence: 0,
    controller: actor.did,
    keyAgreementKey: {
      id: actor.keyAgreementKey.id,
      type: actor.keyAgreementKey.type
    },
    hmac: { id: hmac.id, type: hmac.type }
  }
  if (referenceId !== undefined) {
    config.referenceId = referenceId
  }
  const created = (await EdvClient.createEdv({
    config,
    url: server.edvsUrl,
    invocationSigner: actor.signer
  })) as { id: string }
  const client = new EdvClient({
    id: created.id,
    keyAgreementKey: actor.keyAgreementKey,
    hmac,
    invocationSigner: actor.signer,
    keyResolver
  })
  return { client, edvId: created.id, hmac }
}

/**
 * Performs a signed zcap-invoked HTTP request. Unlike ZcapClient, this
 * helper accepts plain-http invocation targets (the test server runs on
 * `http://localhost`); it mirrors what edv-client's HttpsTransport does.
 *
 * @param options {object}
 * @param options.url {string}
 * @param options.method {string}   'get' | 'post' | 'delete'
 * @param options.action {string}   'read' | 'write'
 * @param options.capability {string|object}   the zcap to invoke
 * @param options.signer {ISigner}
 * @param [options.json] {object}   request body
 * @param [options.headers] {object}   extra (unsigned) request headers
 * @returns {Promise<{status: number, data: unknown, headers: Headers}>}
 */
export async function signedRequest({
  url,
  method,
  action,
  capability,
  signer,
  json,
  headers = {}
}: {
  url: string
  method: string
  action: string
  capability: string | IZcap
  signer: ISigner
  json?: object
  headers?: Record<string, string>
}): Promise<{ status: number; data?: unknown; headers: Headers }> {
  const signedHeaders = await signCapabilityInvocation({
    url,
    method,
    headers: { ...DEFAULT_HEADERS },
    json,
    capability,
    invocationSigner: signer,
    capabilityAction: action
  })
  return httpClient(url, {
    method,
    json,
    headers: { ...signedHeaders, ...headers }
  })
}

/**
 * Extracts the local vault ID from a full EDV URL.
 *
 * @param options {object}
 * @param options.edvId {string}
 * @returns {string}
 */
export function localId({ edvId }: { edvId: string }): string {
  return edvId.slice(edvId.lastIndexOf('/') + 1)
}
