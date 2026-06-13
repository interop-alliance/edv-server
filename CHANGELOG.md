# @interop/edv-server Changelog

## 0.1.0 - 2026-06-13

### Added

- Initial implementation: TypeScript + fastify EDV server with filesystem
  storage (`edvPlugin`, `createApp()`, `start.ts`).
- Full EDV API: vault configs (create / find by referenceId / get / update),
  documents (insert / upsert / get), blinded-index queries (`equals` / `has` /
  `count` / `limit` + `hasMore` / `documentIds`), chunks (store / get / delete),
  and zcap revocations.
- zcap authorization on every route (request-URL expectedTarget, target
  attenuation, chain limits, digest-vs-body check) with per-vault revocation
  checking via `inspectCapabilityChain`.
- Index-free query engine: streaming `Buffer.indexOf` substring pre-filter over
  pretty-printed doc files plus full `docMatches` verification.
- e2e test suites driven by `@interop/edv-client`, including revocation
  semantics ported from ezcap-express.
- Conformance: passes `@interop/edv-conformance-suite` (73 passed, 2 skipped;
  config at `edv-conformance-suite/configs/edv-server.config.ts`).

### Fixed

- Query: an empty `equals` element matches no documents. `@interop/edv-client`
  sends `equals: [{}]` when querying an attribute that was never registered in
  its index; this previously matched every document under the queried index
  (vacuous `every()`), where reference behavior (mongo `$all: []`) is an empty
  result. Surfaced by the conformance suite.
- Revocations: use a default import of `@interop/jsonld-signatures` in the
  delegation-chain verification. The package's named exports are not statically
  detectable on its CJS entry point (through 11.7.1), so under plain node/tsx
  the namespace import had no callable `verify` and every revocation request
  returned 500 -- vitest's CJS interop masked this, so only the standalone
  server was affected. Surfaced by the conformance suite.
