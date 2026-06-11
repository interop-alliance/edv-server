/**
 * Revocation storage: `revocations/<sha256hex(zcapId)>.json` per revoked
 * zcap, plus a lazy in-memory `Set<capabilityId>` cache per vault that is
 * consulted by the `inspectCapabilityChain` hook on every authorization.
 */
import { readdir } from 'node:fs/promises'
import * as path from 'node:path'
import type { IDelegatedZcap } from '@interop/data-integrity-core'
import {
  edvLockKey,
  readJson,
  storageMutex,
  writeJsonAtomic
} from './atomic.js'
import { revocationPath, revocationsDir } from './paths.js'

export interface RevocationRecord {
  capabilityId: string
  delegator: string
  capability: IDelegatedZcap
  meta: { created: number }
}

// lazy per-vault cache of revoked capability IDs
const revokedIdCache = new Map<string, Set<string>>()

function cacheKey({
  dataDir,
  localEdvId
}: {
  dataDir: string
  localEdvId: string
}): string {
  return `${dataDir}:${localEdvId}`
}

/**
 * Stores a revocation for the given vault and updates the in-memory cache.
 * Runs under the vault mutex. Idempotent: re-revoking is a no-op overwrite.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @param options.capability {IDelegatedZcap}   the zcap being revoked
 * @param options.delegator {string}   the delegator from the verified
 *   delegation proof
 * @returns {Promise<void>}
 */
export async function insertRevocation({
  dataDir,
  localEdvId,
  capability,
  delegator
}: {
  dataDir: string
  localEdvId: string
  capability: IDelegatedZcap
  delegator: string
}): Promise<void> {
  const record: RevocationRecord = {
    capabilityId: capability.id,
    delegator,
    capability,
    meta: { created: Date.now() }
  }
  await storageMutex.run(
    edvLockKey({ dataDir, localEdvId }),
    async function insert() {
      await writeJsonAtomic({
        filePath: revocationPath({
          dataDir,
          localEdvId,
          capabilityId: capability.id
        }),
        value: record
      })
      const cached = revokedIdCache.get(cacheKey({ dataDir, localEdvId }))
      if (cached) {
        cached.add(capability.id)
      }
    }
  )
}

/**
 * Returns the set of revoked capability IDs for a vault, loading it from
 * the revocations directory on first use and caching it in memory.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @returns {Promise<Set<string>>}
 */
export async function getRevokedIds({
  dataDir,
  localEdvId
}: {
  dataDir: string
  localEdvId: string
}): Promise<Set<string>> {
  const key = cacheKey({ dataDir, localEdvId })
  const cached = revokedIdCache.get(key)
  if (cached) {
    return cached
  }
  const ids = new Set<string>()
  const dir = revocationsDir({ dataDir, localEdvId })
  let entries: string[] = []
  try {
    entries = await readdir(dir)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw err
    }
  }
  for (const name of entries) {
    if (!name.endsWith('.json') || name.startsWith('.')) {
      continue
    }
    const record = (await readJson({
      filePath: path.join(dir, name)
    })) as RevocationRecord | null
    if (record !== null) {
      ids.add(record.capabilityId)
    }
  }
  revokedIdCache.set(key, ids)
  return ids
}
