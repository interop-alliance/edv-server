/**
 * ID and response helpers, ported from bedrock-edv-storage `lib/helpers.js`.
 * EDV-local IDs (vault IDs, document IDs) are multibase base58btc-encoded
 * multicodec identity-tagged 16-byte random values.
 */
import { randomBytes } from 'node:crypto'
import { promisify } from 'node:util'
import * as base58 from 'base58-universal'
import etag from 'etag'
import type { FastifyReply } from 'fastify'
import { EdvError } from './errors.js'

const getRandomBytes = promisify(randomBytes)

/**
 * Asserts that the given ID is a base58-encoded multibase, multicodec array
 * of 16 random bytes (a 128-bit identifier). Throws a 400 error if not.
 * Every ID used as a path segment passes through this check, which also
 * makes the IDs filesystem-safe by construction (base58 alphabet only).
 *
 * @param options {object}
 * @param options.id {string}   the identifier to validate
 */
export function assert128BitId({ id }: { id: string }): void {
  try {
    // verify ID is base58-encoded multibase multicodec encoded 16 bytes
    const buf = base58.decode(id.slice(1))
    // multibase base58 (starts with 'z')
    // 128-bit random number, multicodec encoded
    // 0x00 = identity tag, 0x10 = length (16 bytes) + 16 random bytes
    if (
      !(
        id.startsWith('z') &&
        buf.length === 18 &&
        buf[0] === 0x00 &&
        buf[1] === 0x10
      )
    ) {
      throw new Error('Invalid identifier.')
    }
  } catch {
    throw new EdvError({
      message:
        `Identifier "${id}" must be base58-encoded multibase, ` +
        'multicodec array of 16 random bytes.',
      name: 'SyntaxError',
      httpStatusCode: 400
    })
  }
}

/**
 * Generates a new random, multibase base58-encoded 128-bit local identifier.
 *
 * @returns {Promise<string>} the encoded identifier (prefixed with `z`)
 */
export async function generateLocalId(): Promise<string> {
  // 128-bit random number, multibase encoded
  // 0x00 = identity tag, 0x10 = length (16 bytes)
  const buf = Buffer.concat([
    Buffer.from([0x00, 0x10]),
    await getRandomBytes(16)
  ])
  // multibase encoding for base58 starts with 'z'
  return `z${base58.encode(buf)}`
}

/**
 * Validates that the given sequence number is a non-negative safe integer
 * below `Number.MAX_SAFE_INTEGER`. Throws if it is not.
 *
 * @param options {object}
 * @param options.sequence {number}   the sequence number to validate
 */
export function validateDocSequence({ sequence }: { sequence: number }): void {
  // sequence is limited to MAX_SAFE_INTEGER - 1 to avoid unexpected
  // behavior when a client attempts to increment the sequence number
  if (!Number.isSafeInteger(sequence) || sequence >= Number.MAX_SAFE_INTEGER) {
    throw new TypeError('"doc.sequence" number is too large.')
  }
  if (sequence < 0) {
    throw new TypeError('"doc.sequence" must be a non-negative integer.')
  }
}

/**
 * Sends a JSON response with an ETag and cache headers set so the response
 * can be revalidated by clients via conditional requests.
 *
 * @param options {object}
 * @param options.reply {FastifyReply}   the fastify reply to write to
 * @param options.obj {object}   the object to serialize and send as JSON
 */
export async function sendCacheableJson({
  reply,
  obj
}: {
  reply: FastifyReply
  obj: object
}): Promise<void> {
  const body = Buffer.from(JSON.stringify(obj), 'utf8')
  const etagValue = etag(body)
  // "private": store in per-user cache only
  // "no-cache": client must perform the request again, but should send the
  // e-tag so the request can be revalidated against it
  reply.header('cache-control', 'private, no-cache')
  reply.header('etag', etagValue)
  if (reply.request.headers['if-none-match'] === etagValue) {
    await reply.status(304).send()
    return
  }
  reply.header('content-type', 'application/json')
  await reply.send(body)
}
