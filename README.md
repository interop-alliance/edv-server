# EDV Server _(@interop/edv-server)_

> An Encrypted Data Vault (EDV) server: a fastify plugin plus standalone server,
> with filesystem storage.

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [HTTP API](#http-api)
- [Authorization model](#authorization-model)
- [On-disk layout](#on-disk-layout)
- [Queries](#queries)
- [Known gaps and tradeoffs](#known-gaps-and-tradeoffs)
- [Contribute](#contribute)
- [License](#license)

## Background

This server implements the
[Encrypted Data Vault](https://digitalbazaar.github.io/encrypted-data-vaults/)
protocol: it stores client-side-encrypted documents and binary chunks, supports
privacy-preserving queries over HMAC-blinded ("encrypted") indexes, and
authorizes every request with zcaps (Authorization Capabilities) invoked via
HTTP signatures -- including full **zcap revocation** support.

The wire contract is `@interop/edv-client` (`EdvClient`, `EdvDocument`,
`HttpsTransport`); the protocol semantics (routes, status codes, integrity
invariants, query behavior) follow Digital Bazaar's `bedrock-edv-storage`
reference implementation, minus the Bedrock plumbing (no metering, no
`ipAllowList`, no legacy document-version migration).

Storage is **plain JSON files on disk**, chosen for developer experience:
perform an EDV request, then inspect the results directly with `tree`, `cat` and
`jq`. There are no index files and no database -- the documents on disk are the
only state.

The server never sees key material: `keyAgreementKey` and `hmac` in a vault
config are opaque references the client uses to decrypt content and to blind
index attributes.

## Install

- Node.js 24+ is required.

```
pnpm install @interop/edv-server
```

To install locally (for development):

```
git clone https://github.com/interop-alliance/edv-server.git
cd edv-server
pnpm install
```

## Usage

### Standalone server

```
pnpm dev        # tsx watch mode
# or
pnpm build && pnpm start
```

Environment configuration:

| Variable           | Default                 |
| ------------------ | ----------------------- |
| `PORT`             | `5000`                  |
| `EDV_BASE_URL`     | `http://localhost:PORT` |
| `EDV_DATA_DIR`     | `./data`                |
| `EDV_ROUTE_PREFIX` | `/edvs`                 |

`EDV_BASE_URL` must match the URL clients use to reach the server: EDV IDs are
absolute URLs derived from it, and zcap invocation targets and host checks are
URL-based.

### As a fastify plugin

```ts
import { fastify } from 'fastify'
import { edvPlugin } from '@interop/edv-server'

const app = fastify({
  // validation must reject (not strip) unknown body properties, and must
  // never mutate request bodies (the digest check compares the parsed body
  // to what the client signed)
  ajv: {
    customOptions: {
      removeAdditional: false,
      coerceTypes: false,
      allowUnionTypes: true
    }
  }
})
await app.register(edvPlugin, {
  baseUrl: 'https://storage.example.com',
  dataDir: './data',
  routePrefix: '/edvs' // default
})
```

Or use `createApp()`, which applies the required ajv options for you:

```ts
import { createApp } from '@interop/edv-server'

const app = createApp({
  baseUrl: 'http://localhost:5000',
  dataDir: './data',
  fastifyOptions: { logger: true }
})
await app.listen({ port: 5000 })
```

### Driving it with @interop/edv-client

```ts
import { EdvClient } from '@interop/edv-client'

const config = await EdvClient.createEdv({
  url: 'http://localhost:5000/edvs',
  invocationSigner, // a did:key capabilityInvocation signer
  config: {
    sequence: 0,
    controller: did,
    keyAgreementKey: { id: keyAgreementKey.id, type: keyAgreementKey.type },
    hmac: { id: hmac.id, type: hmac.type }
  }
})
const client = new EdvClient({
  id: config.id,
  keyAgreementKey,
  hmac,
  invocationSigner,
  keyResolver
})
await client.insert({ doc: { id: await EdvClient.generateId(), content } })
```

## HTTP API

Base path `/edvs` (configurable). All endpoints are CORS-enabled and
zcap-authorized. Body limit is 10 MB on document and chunk writes.

| Method + path                                             | Action                                                       |
| --------------------------------------------------------- | ------------------------------------------------------------ |
| `POST /edvs`                                              | create vault (201 + Location; server assigns `id`)           |
| `GET /edvs?controller=...&referenceId=...`                | find configs (`[config]` or `[]`)                            |
| `GET /edvs/:edvId`                                        | get config                                                   |
| `POST /edvs/:edvId`                                       | update config (sequence previous+1; `referenceId` immutable) |
| `POST /edvs/:edvId/documents`                             | insert doc (201; 409 on duplicate)                           |
| `POST /edvs/:edvId/documents/:docId`                      | update (upsert) doc (204; 409 on sequence mismatch)          |
| `GET /edvs/:edvId/documents/:docId`                       | get doc (ETag + `cache-control: private, no-cache`)          |
| `POST /edvs/:edvId/query` (also `/documents/query`)       | query by blinded index (zcap action `read`)                  |
| `POST /edvs/:edvId/documents/:docId/chunks/:chunkIndex`   | store chunk (204; sequence must equal the doc's)             |
| `GET /edvs/:edvId/documents/:docId/chunks/:chunkIndex`    | get chunk                                                    |
| `DELETE /edvs/:edvId/documents/:docId/chunks/:chunkIndex` | delete chunk (204 / 404)                                     |
| `POST /edvs/:edvId/zcaps/revocations/:revocationId`       | revoke a delegated zcap (204)                                |

There is no HTTP DELETE for documents: deletion is a client-side concept (the
client updates the doc to an encrypted tombstone). Errors are `{name, message}`
JSON; clients should rely on the status codes (400 / 403 / 404 / 409).

## Authorization model

Every request must carry a signed capability invocation (HTTP Signatures +
`capability-invocation` header; see `@interop/ezcap` for the client side). The
server verifies the signature, the delegation chain (target attenuation allowed,
max chain length 10, max delegation TTL 1 year, 300 s clock skew), the `digest`
header against the request body, and revocation status.

- The **root zcap** for a vault is never stored; it is synthesized on demand
  with id `urn:zcap:root:<urlencoded vault URL>` and controller := the vault
  config's `controller`. A capability for the vault (or a delegation attenuated
  to a narrower target under it) covers all of the vault's sub-resources.
- **Vault creation is self-provisioning** (this replaces Bedrock's
  metering-based authority): the root zcap for `POST /edvs` is synthesized with
  controller := the posted `config.controller`, so creating a vault means
  proving control of the key you claim as its controller. Similarly,
  `GET /edvs?controller=...` uses the `controller` query parameter as the root
  controller. Anyone with a did:key can create vaults -- quota/access control is
  deliberately out of scope for this development server.
- **Revocation**: `POST /edvs/:edvId/zcaps/revocations/:revocationId` lets _any
  participant in a zcap's delegation chain_ revoke it (the to-be-revoked zcap's
  chain is verified first; its controllers become the controllers of the
  zcap-specific root capability). Revocations are persisted per vault and
  consulted on every verification.

## On-disk layout

```
<dataDir>/edvs/<localEdvId>/
  config.json                       # IEDVConfig verbatim
  docs/<docId>.json                 # IEncryptedDocument verbatim
  chunks/<docId>/<chunkIndex>.json  # IEDVChunk verbatim
  revocations/<sha256hex(zcapId)>.json
```

Everything is pretty-printed (2-space) JSON, stored verbatim as sent by the
client. All path segments are validated before use (IDs are base58 multibase
128-bit values, chunk indexes are decimal integers), so paths are
filesystem-safe by construction.

Writes are atomic (temp file + rename) and serialized per vault by an in-process
mutex; sequence/duplicate/uniqueness invariants are enforced inside that lock.
**No fsync** is performed -- a crash can lose the most recent write. That is an
intentional development-server tradeoff; do not point this at data you cannot
recreate.

## Queries

Queries (`equals` / `has` / `count` / `limit`) use full-scan semantics with no
index files: a streaming `Buffer.indexOf` substring pre-filter selects candidate
doc files (sound because blinded attribute strings appear literally in the
stored JSON), then candidates are parsed and fully evaluated. The same machinery
enforces `unique: true` blinded-attribute conflicts at write time.

Full scan is O(vault size) per query -- fine to roughly 10k documents per vault.
The growth path, if ever needed, is a rebuildable JSON inverted-index cache; the
docs on disk remain the only source of truth.

## Known gaps and tradeoffs

- `POST /edvs/:edvId/documents/:docId/index` (edv-client's `updateIndex`) is not
  supported -- the reference server does not support it either.
- No pagination cursor on queries (reference parity): `limit` + `hasMore` only.
- No durability (no fsync) -- see above.
- The digest check assumes `JSON.parse`/`JSON.stringify` round-trips the
  client's body bytes (the same assumption ezcap-express makes).

## Contribute

PRs accepted.

## License

[MIT](LICENSE.md) © 2026 Interop Alliance.
