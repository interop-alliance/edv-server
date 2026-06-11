/**
 * HTTP-signature key resolution and proof suite for zcap verification:
 * resolves `did:key` key IDs to Ed25519 verifiers and creates the
 * Ed25519Signature2020 suite used to verify delegation chains.
 */
import * as didKey from '@interop/did-method-key'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import type {
  IPublicKey,
  IVerificationMethod,
  IVerifier
} from '@interop/data-integrity-core'

const didKeyDriver = didKey.driver()
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey.from
})

/**
 * Resolves the invocation signature's keyId to an Ed25519 verifier.
 *
 * @param options {object}
 * @param options.keyId {string}   the did:key verification method URL
 * @returns {Promise<{verifier: IVerifier,
 *   verificationMethod: IVerificationMethod}>}
 */
export async function getVerifier({ keyId }: { keyId: string }): Promise<{
  verifier: IVerifier
  verificationMethod: IVerificationMethod
}> {
  const verificationMethod = await didKeyDriver.get({ url: keyId })
  const key = await Ed25519VerificationKey.from(
    verificationMethod as IPublicKey
  )
  const verifier = key.verifier()
  return {
    verifier,
    verificationMethod: verificationMethod as IVerificationMethod
  }
}

/**
 * Creates the signature suite used to verify zcap delegation chains.
 *
 * @returns {Ed25519Signature2020}
 */
export function createSuite(): Ed25519Signature2020 {
  return new Ed25519Signature2020()
}
