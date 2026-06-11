/**
 * JSON Schemas for every request body / query string, translated from
 * bedrock-edv-storage `schemas/bedrock-edv-storage.js`. They are the
 * protocol's wire-format source of truth.
 *
 * Differences from the bedrock originals:
 * - tuple-form `items: [{...}]` (which validates only the first array
 *   element) is fixed to object form, validating every element;
 * - `meterId` is accepted and ignored (optional, never required);
 * - `ipAllowList` is dropped.
 */

const id = { title: 'id', type: 'string' } as const

const controller = { title: 'controller', type: 'string' } as const

const referenceId = { title: 'referenceId', type: 'string' } as const

const sequence = {
  title: 'sequence',
  type: 'integer',
  minimum: 0,
  maximum: Number.MAX_SAFE_INTEGER - 1
} as const

const keyReference = {
  type: 'object',
  required: ['id', 'type'],
  additionalProperties: false,
  properties: {
    id,
    type: { type: 'string' }
  }
} as const

/**
 * Corresponds to @interop/data-integrity-core IEDVConfig. `meterId` is
 * accepted for bedrock client compatibility but ignored by this server.
 */
export const edvConfig = {
  title: 'EDV Configuration',
  type: 'object',
  required: ['controller', 'sequence', 'keyAgreementKey', 'hmac'],
  additionalProperties: false,
  properties: {
    id,
    controller,
    keyAgreementKey: keyReference,
    hmac: { title: 'hmac', ...keyReference },
    meterId: { title: 'Meter ID', type: 'string' },
    referenceId,
    sequence
  }
} as const

/**
 * Corresponds to @interop/data-integrity-core IJWE.
 */
export const jwe = {
  title: 'JWE with at least one recipient',
  type: 'object',
  required: ['protected', 'recipients', 'iv', 'ciphertext', 'tag'],
  additionalProperties: false,
  properties: {
    protected: { type: 'string' },
    recipients: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        required: ['header', 'encrypted_key'],
        additionalProperties: false,
        properties: {
          header: {
            type: 'object',
            required: ['alg', 'kid'],
            properties: {
              alg: { type: 'string' },
              kid: { type: 'string' },
              epk: { type: 'object' },
              apu: { type: 'string' },
              apv: { type: 'string' }
            }
          },
          encrypted_key: { type: 'string' }
        }
      }
    },
    iv: { type: 'string' },
    ciphertext: { type: 'string' },
    tag: { type: 'string' }
  }
} as const

/**
 * Corresponds to @interop/data-integrity-core IIndexEntry (the `attributes`
 * items correspond to IIndexAttribute).
 */
export const indexedEntry = {
  title: 'EDV Indexed Entry',
  type: 'object',
  required: ['hmac', 'sequence', 'attributes'],
  additionalProperties: false,
  properties: {
    hmac: { title: 'hmac', ...keyReference },
    sequence,
    attributes: {
      type: 'array',
      items: {
        type: 'object',
        required: ['name', 'value'],
        additionalProperties: false,
        properties: {
          name: { type: 'string' },
          value: { type: 'string' },
          unique: { type: 'boolean' }
        }
      }
    }
  }
} as const

/**
 * Corresponds to @interop/data-integrity-core IEncryptedDocument (the
 * encrypted, server-stored form -- not the decrypted IEDVDocument).
 */
export const edvDocument = {
  title: 'EDV Document',
  type: 'object',
  required: ['id', 'sequence', 'jwe'],
  additionalProperties: false,
  properties: {
    id,
    sequence,
    indexed: {
      type: 'array',
      items: indexedEntry
    },
    jwe,
    // the client rewrites the cleartext `stream` to `{sequence, chunks}`
    // before sending; on the first write of a streamed doc this yields
    // `stream: {}`, which is valid here
    stream: {
      type: 'object',
      additionalProperties: false,
      properties: {
        sequence: { type: 'integer', minimum: 0 },
        chunks: { type: 'integer', minimum: 1 }
      }
    }
  }
} as const

/**
 * Corresponds to @interop/data-integrity-core IEDVChunk.
 */
export const edvDocumentChunk = {
  title: 'EDV Document Chunk',
  type: 'object',
  required: ['index', 'jwe', 'offset', 'sequence'],
  additionalProperties: false,
  properties: {
    index: { type: 'integer', minimum: 0 },
    jwe,
    offset: { type: 'integer', minimum: 0 },
    sequence
  }
} as const

/**
 * Corresponds to @interop/data-integrity-core IEDVQuery.
 */
export const edvDocumentQuery = {
  title: 'EDV Document Query',
  type: 'object',
  required: ['index'],
  anyOf: [{ required: ['equals'] }, { required: ['has'] }],
  additionalProperties: false,
  properties: {
    index: { type: 'string' },
    count: { title: 'EDV Query Count', type: 'boolean' },
    equals: {
      type: 'array',
      minItems: 1,
      items: {
        type: 'object',
        // items are `name: value` pairs where names are free-form and
        // values must be (blinded) strings
        additionalProperties: { type: 'string' }
      }
    },
    has: {
      type: 'array',
      minItems: 1,
      items: { type: 'string' }
    },
    returnDocuments: { type: 'boolean' },
    limit: { type: 'integer', minimum: 1, maximum: 1000 }
  }
} as const

/**
 * Query string for listing EDV configs by controller + referenceId.
 */
export const getConfigsQuery = {
  title: 'edv query',
  type: 'object',
  required: ['controller', 'referenceId'],
  additionalProperties: false,
  properties: {
    controller,
    referenceId
  }
} as const

/**
 * Corresponds to @interop/data-integrity-core IDelegatedZcap (the `proof`
 * object corresponds to ICapabilityDelegationProof). Assumes
 * Ed25519Signature2020 proofs, so `proof.cryptosuite` is intentionally
 * absent.
 */
export const delegatedZcap = {
  title: 'delegatedZcap',
  type: 'object',
  additionalProperties: false,
  required: [
    '@context',
    'controller',
    'expires',
    'id',
    'invocationTarget',
    'parentCapability',
    'proof'
  ],
  properties: {
    controller,
    id,
    allowedAction: {
      anyOf: [
        { type: 'string' },
        { type: 'array', minItems: 1, items: { type: 'string' } }
      ]
    },
    expires: { title: 'expires', type: 'string' },
    '@context': {
      title: '@context',
      anyOf: [
        { type: 'string' },
        { type: 'array', minItems: 1, items: { type: 'string' } }
      ]
    },
    invocationTarget: { title: 'Invocation Target', type: 'string' },
    parentCapability: { title: 'Parent Capability', type: 'string' },
    proof: {
      title: 'Proof',
      type: 'object',
      additionalProperties: false,
      required: [
        'verificationMethod',
        'type',
        'created',
        'proofPurpose',
        'capabilityChain',
        'proofValue'
      ],
      properties: {
        verificationMethod: { title: 'verificationMethod', type: 'string' },
        type: { title: 'type', type: 'string' },
        created: { title: 'created', type: 'string' },
        proofPurpose: { title: 'proofPurpose', type: 'string' },
        capabilityChain: {
          title: 'capabilityChain',
          type: 'array',
          minItems: 1,
          items: { type: ['string', 'object'] }
        },
        proofValue: { title: 'proofValue', type: 'string' }
      }
    },
    referenceId
  }
} as const

export {
  edvConfig as postConfigBody,
  edvDocumentChunk as postChunkBody,
  edvDocument as postDocumentBody,
  edvDocumentQuery as postDocumentQueryBody,
  delegatedZcap as postRevocationBody
}
