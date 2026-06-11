import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import * as path from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { IEncryptedDocument } from '@interop/data-integrity-core'
import { generateLocalId } from '../src/helpers.js'
import { insertConfig } from '../src/storage/edvs.js'
import { insertDoc } from '../src/storage/docs.js'
import {
  countDocs,
  docMatches,
  findDocs,
  scanFileForTerms
} from '../src/storage/query.js'
import { docPath } from '../src/storage/paths.js'

const BASE = 'https://edv.example/edvs'
const HMAC_A = 'urn:hmac:aaa'
const HMAC_B = 'urn:hmac:bbb'

let dataDir: string
let localEdvId: string

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

function makeDoc({
  id,
  attributes,
  hmacId = HMAC_A
}: {
  id: string
  attributes: Array<{ name: string; value: string; unique?: boolean }>
  hmacId?: string
}): IEncryptedDocument {
  return {
    id,
    sequence: 0,
    jwe: mockJwe(),
    indexed: [
      {
        hmac: { id: hmacId, type: 'Sha256HmacKey2019' },
        sequence: 0,
        attributes
      }
    ]
  }
}

beforeAll(async () => {
  dataDir = await mkdtemp(path.join(tmpdir(), 'edv-query-test-'))
  const localId = await generateLocalId()
  await insertConfig({
    dataDir,
    config: {
      id: `${BASE}/${localId}`,
      controller: 'did:key:z6MkExample',
      sequence: 0,
      keyAgreementKey: { id: 'urn:kak:1', type: 'X25519KeyAgreementKey2020' },
      hmac: { id: HMAC_A, type: 'Sha256HmacKey2019' }
    }
  })
  localEdvId = localId
})

afterAll(async () => {
  await rm(dataDir, { recursive: true, force: true })
})

describe('docMatches', () => {
  const doc = makeDoc({
    id: 'z19pjdSMQNkBqqJ5zsbbgbbbb',
    attributes: [
      { name: 'bCountry', value: 'bFrance' },
      { name: 'bColor', value: 'bBlue' }
    ]
  })

  it('matches equals as AND of pairs within an element', () => {
    expect(
      docMatches({
        doc,
        query: {
          index: HMAC_A,
          equals: [{ bCountry: 'bFrance', bColor: 'bBlue' }]
        }
      })
    ).toBe(true)
    expect(
      docMatches({
        doc,
        query: {
          index: HMAC_A,
          equals: [{ bCountry: 'bFrance', bColor: 'bRed' }]
        }
      })
    ).toBe(false)
  })

  it('matches equals as OR across elements', () => {
    expect(
      docMatches({
        doc,
        query: {
          index: HMAC_A,
          equals: [{ bColor: 'bRed' }, { bCountry: 'bFrance' }]
        }
      })
    ).toBe(true)
  })

  it('scopes equals to the queried hmac id', () => {
    expect(
      docMatches({
        doc,
        query: { index: HMAC_B, equals: [{ bCountry: 'bFrance' }] }
      })
    ).toBe(false)
  })

  it('matches has when all names are present', () => {
    expect(
      docMatches({
        doc,
        query: { index: HMAC_A, has: ['bCountry', 'bColor'] }
      })
    ).toBe(true)
    expect(
      docMatches({
        doc,
        query: { index: HMAC_A, has: ['bCountry', 'bMissing'] }
      })
    ).toBe(false)
  })

  it('does not cross name/value pairs between attributes', () => {
    expect(
      docMatches({
        doc,
        query: { index: HMAC_A, equals: [{ bCountry: 'bBlue' }] }
      })
    ).toBe(false)
  })
})

describe('scanFileForTerms', () => {
  it('finds terms that straddle stream chunk boundaries', async () => {
    // build a doc whose attribute value is long and sits past 64KB so the
    // overlap-carry logic is exercised
    const filler = 'x'.repeat(70 * 1024)
    const needle = 'bNeedleValueThatIsLongEnoughToStraddle'
    const id = await generateLocalId()
    const doc = makeDoc({
      id,
      attributes: [
        { name: 'bFiller', value: filler },
        { name: 'bNeedle', value: needle }
      ]
    })
    await insertDoc({ dataDir, localEdvId, doc })
    const filePath = docPath({ dataDir, localEdvId, docId: id })
    const [found] = await scanFileForTerms({
      filePath,
      terms: [Buffer.from(needle, 'utf8')]
    })
    expect(found).toBe(true)
    const [missing] = await scanFileForTerms({
      filePath,
      terms: [Buffer.from('bNotPresentAnywhere', 'utf8')]
    })
    expect(missing).toBe(false)
  })
})

describe('findDocs / countDocs', () => {
  const ids: Record<string, string> = {}

  beforeAll(async () => {
    // fresh vault for isolation
    const localId = await generateLocalId()
    await insertConfig({
      dataDir,
      config: {
        id: `${BASE}/${localId}`,
        controller: 'did:key:z6MkExample',
        sequence: 0,
        keyAgreementKey: { id: 'urn:kak:1', type: 'X25519KeyAgreementKey2020' },
        hmac: { id: HMAC_A, type: 'Sha256HmacKey2019' }
      }
    })
    localEdvId = localId

    for (const [key, attributes] of Object.entries({
      franceBlue: [
        { name: 'bCountry', value: 'bFrance' },
        { name: 'bColor', value: 'bBlue' }
      ],
      franceRed: [
        { name: 'bCountry', value: 'bFrance' },
        { name: 'bColor', value: 'bRed' }
      ],
      spain: [{ name: 'bCountry', value: 'bSpain' }],
      noIndex: []
    })) {
      const id = await generateLocalId()
      ids[key] = id
      const doc =
        key === 'noIndex'
          ? { id, sequence: 0, jwe: mockJwe(), indexed: [] }
          : makeDoc({ id, attributes })
      await insertDoc({ dataDir, localEdvId, doc })
    }

    // crafted pre-filter false positive: the *ciphertext* contains the
    // blinded search strings, but the doc has no matching indexed
    // attribute -- the verify step must reject it
    const falsePositiveId = await generateLocalId()
    ids.falsePositive = falsePositiveId
    await insertDoc({
      dataDir,
      localEdvId,
      doc: {
        id: falsePositiveId,
        sequence: 0,
        jwe: {
          ...mockJwe(),
          ciphertext: `${HMAC_A}-bCountry-bFrance-bSpain-lookalike`
        },
        indexed: []
      }
    })
  })

  it('finds docs by equals', async () => {
    const { documents, hasMore } = await findDocs({
      dataDir,
      localEdvId,
      query: { index: HMAC_A, equals: [{ bCountry: 'bFrance' }] }
    })
    expect(documents.map(doc => doc.id).sort()).toEqual(
      [ids.franceBlue, ids.franceRed].sort()
    )
    expect(hasMore).toBe(false)
  })

  it('excludes pre-filter false positives via the verify step', async () => {
    const { documents } = await findDocs({
      dataDir,
      localEdvId,
      query: { index: HMAC_A, equals: [{ bCountry: 'bSpain' }] }
    })
    expect(documents.map(doc => doc.id)).toEqual([ids.spain])
  })

  it('finds docs by has', async () => {
    const { documents } = await findDocs({
      dataDir,
      localEdvId,
      query: { index: HMAC_A, has: ['bCountry', 'bColor'] }
    })
    expect(documents.map(doc => doc.id).sort()).toEqual(
      [ids.franceBlue, ids.franceRed].sort()
    )
  })

  it('counts docs', async () => {
    expect(
      await countDocs({
        dataDir,
        localEdvId,
        query: { index: HMAC_A, equals: [{ bCountry: 'bFrance' }] }
      })
    ).toBe(2)
  })

  it('applies limit + hasMore', async () => {
    const { documents, hasMore } = await findDocs({
      dataDir,
      localEdvId,
      query: { index: HMAC_A, equals: [{ bCountry: 'bFrance' }], limit: 1 }
    })
    expect(documents).toHaveLength(1)
    expect(hasMore).toBe(true)
  })

  it('ORs across equals elements', async () => {
    const { documents } = await findDocs({
      dataDir,
      localEdvId,
      query: {
        index: HMAC_A,
        equals: [{ bCountry: 'bSpain' }, { bColor: 'bBlue' }]
      }
    })
    expect(documents.map(doc => doc.id).sort()).toEqual(
      [ids.franceBlue, ids.spain].sort()
    )
  })
})
