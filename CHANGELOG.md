# @interop/edv-server Changelog

## 0.0.1 - TBD

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
