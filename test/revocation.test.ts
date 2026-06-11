/**
 * zcap revocation tests (model: bedrock-edv-storage
 * `test/mocha/30-revocation.js`): attenuated delegation, revocation by the
 * delegator, self-revocation by the delegate, and the failure modes (root
 * zcaps, foreign vaults).
 */
import { readdir } from 'node:fs/promises'
import * as fsPath from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EdvClient } from '@interop/edv-client'
import type { IDelegatedZcap } from '@interop/data-integrity-core'
import {
  type Actor,
  createActor,
  createEdv,
  keyResolver,
  localId,
  SEEDS,
  signedRequest,
  startTestServer,
  type TestServer
} from './helpers.js'

let server: TestServer
let alice: Actor
let bob: Actor

beforeAll(async () => {
  server = await startTestServer()
  alice = await createActor({ seed: SEEDS.alice })
  bob = await createActor({ seed: SEEDS.bob })
})

afterAll(async () => {
  await server.close()
})

function rootZcapOf({ edvId }: { edvId: string }): string {
  return `urn:zcap:root:${encodeURIComponent(edvId)}`
}

async function setupVaultWithDoc() {
  const { client, edvId } = await createEdv({ server, actor: alice })
  const docId = await EdvClient.generateId()
  await client.insert({
    doc: { id: docId, content: { secret: 'between alice and bob' } },
    invocationSigner: alice.signer,
    keyResolver
  })
  const docUrl = `${edvId}/documents/${docId}`
  return { client, edvId, docId, docUrl }
}

async function delegateDocRead({
  edvId,
  docUrl,
  to
}: {
  edvId: string
  docUrl: string
  to: Actor
}): Promise<IDelegatedZcap> {
  // attenuated delegation: the chain is rooted at the *vault*, but the
  // delegated zcap narrows the invocation target to one document
  return alice.zcapClient.delegate({
    capability: rootZcapOf({ edvId }),
    invocationTarget: docUrl,
    controller: to.did,
    expires: new Date(Date.now() + 60 * 60 * 1000),
    allowedActions: ['read']
  })
}

async function bobReadsDoc({
  docUrl,
  capability
}: {
  docUrl: string
  capability: IDelegatedZcap
}) {
  return signedRequest({
    url: docUrl,
    method: 'get',
    action: 'read',
    capability,
    signer: bob.signer
  })
}

describe('zcap revocations', () => {
  it('alice revokes a doc-scoped zcap she delegated to bob', async () => {
    const { client, edvId, docUrl } = await setupVaultWithDoc()
    const delegated = await delegateDocRead({ edvId, docUrl, to: bob })

    // bob can read the doc with the attenuated delegated zcap
    const readResponse = await bobReadsDoc({ docUrl, capability: delegated })
    expect(readResponse.status).toBe(200)

    // alice revokes bob's zcap
    await client.revokeCapability({
      capabilityToRevoke: delegated,
      invocationSigner: alice.signer
    })

    // DX: the revocation file appears on disk
    const revocationsDir = fsPath.join(
      server.dataDir,
      'edvs',
      localId({ edvId }),
      'revocations'
    )
    const revocationFiles = await readdir(revocationsDir)
    expect(revocationFiles).toHaveLength(1)

    // bob's reads are now rejected
    await expect(
      bobReadsDoc({ docUrl, capability: delegated })
    ).rejects.toMatchObject({ status: 403 })
  })

  it('bob can self-revoke a zcap delegated to him', async () => {
    const { edvId, docUrl } = await setupVaultWithDoc()
    const delegated = await delegateDocRead({ edvId, docUrl, to: bob })
    expect((await bobReadsDoc({ docUrl, capability: delegated })).status).toBe(
      200
    )

    // bob revokes his own zcap (he is a chain controller)
    const bobEdvClient = new EdvClient({
      id: edvId,
      invocationSigner: bob.signer,
      keyResolver
    })
    await bobEdvClient.revokeCapability({
      capabilityToRevoke: delegated,
      invocationSigner: bob.signer
    })

    await expect(
      bobReadsDoc({ docUrl, capability: delegated })
    ).rejects.toMatchObject({ status: 403 })
  })

  it('rejects re-revoking an already-revoked zcap (reference parity)', async () => {
    const { client, edvId, docUrl } = await setupVaultWithDoc()
    const delegated = await delegateDocRead({ edvId, docUrl, to: bob })
    await client.revokeCapability({
      capabilityToRevoke: delegated,
      invocationSigner: alice.signer
    })
    // the delegation chain now contains a revoked capability, so the
    // chain verify itself fails (ezcap-express behaves the same way)
    await expect(
      client.revokeCapability({
        capabilityToRevoke: delegated,
        invocationSigner: alice.signer
      })
    ).rejects.toMatchObject({ status: 400 })
  })

  it('400s an attempt to revoke a root zcap', async () => {
    const { edvId } = await setupVaultWithDoc()
    const rootId = rootZcapOf({ edvId })
    const url = `${edvId}/zcaps/revocations/${encodeURIComponent(rootId)}`
    await expect(
      signedRequest({
        url,
        method: 'post',
        action: 'write',
        capability: rootZcapOf({ edvId }),
        signer: alice.signer,
        json: {
          '@context': 'https://w3id.org/zcap/v1',
          id: rootId,
          controller: alice.did,
          invocationTarget: edvId
        }
      })
    ).rejects.toMatchObject({ status: 400 })
  })

  it('403s revoking a zcap rooted at another vault', async () => {
    const { edvId: vault1 } = await setupVaultWithDoc()
    // a zcap rooted at a *different* vault
    const { edvId: vault2, docUrl: vault2DocUrl } = await setupVaultWithDoc()
    const foreignZcap = await delegateDocRead({
      edvId: vault2,
      docUrl: vault2DocUrl,
      to: bob
    })

    // posting it to vault1's revocation endpoint must fail
    const url =
      `${vault1}/zcaps/revocations/` + encodeURIComponent(foreignZcap.id)
    await expect(
      signedRequest({
        url,
        method: 'post',
        action: 'write',
        capability: `urn:zcap:root:${encodeURIComponent(url)}`,
        signer: alice.signer,
        json: foreignZcap
      })
    ).rejects.toMatchObject({ status: 403 })

    // and the foreign zcap still works at its own vault
    const readResponse = await signedRequest({
      url: vault2DocUrl,
      method: 'get',
      action: 'read',
      capability: foreignZcap,
      signer: bob.signer
    })
    expect(readResponse.status).toBe(200)
  })

  it('rejects a revocation submitted by a non-participant', async () => {
    const { edvId, docUrl } = await setupVaultWithDoc()
    const delegated = await delegateDocRead({ edvId, docUrl, to: bob })
    // mallory is neither the vault controller nor in the chain
    const mallory = await createActor({ seed: new Uint8Array(32).fill(3) })
    const url = `${edvId}/zcaps/revocations/` + encodeURIComponent(delegated.id)
    await expect(
      signedRequest({
        url,
        method: 'post',
        action: 'write',
        capability: `urn:zcap:root:${encodeURIComponent(url)}`,
        signer: mallory.signer,
        json: delegated
      })
    ).rejects.toMatchObject({ status: 403 })
    // bob can still read
    expect((await bobReadsDoc({ docUrl, capability: delegated })).status).toBe(
      200
    )
  })

  it('a zcap delegated from a revoked zcap is also rejected', async () => {
    const { client, edvId, docUrl } = await setupVaultWithDoc()
    const delegated = await delegateDocRead({ edvId, docUrl, to: bob })
    // bob re-delegates to carol
    const carol = await createActor({ seed: new Uint8Array(32).fill(4) })
    const subDelegated = await bob.zcapClient.delegate({
      capability: delegated,
      controller: carol.did,
      expires: new Date(Date.now() + 30 * 60 * 1000),
      allowedActions: ['read']
    })
    const carolRead = await signedRequest({
      url: docUrl,
      method: 'get',
      action: 'read',
      capability: subDelegated,
      signer: carol.signer
    })
    expect(carolRead.status).toBe(200)

    // alice revokes bob's zcap (the parent); carol's chain now contains a
    // revoked capability
    await client.revokeCapability({
      capabilityToRevoke: delegated,
      invocationSigner: alice.signer
    })
    await expect(
      signedRequest({
        url: docUrl,
        method: 'get',
        action: 'read',
        capability: subDelegated,
        signer: carol.signer
      })
    ).rejects.toMatchObject({ status: 403 })
  })
})
