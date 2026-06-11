/**
 * EDV config storage: one `config.json` per vault directory. There is no
 * separate referenceId mapping file -- (controller, referenceId) uniqueness
 * is enforced by scanning all vault configs under the create lock.
 */
import { readdir } from 'node:fs/promises'
import type { IEDVConfig } from '@interop/data-integrity-core'
import { DuplicateError, InvalidStateError, NotFoundError } from '../errors.js'
import {
  createLockKey,
  edvLockKey,
  readJson,
  storageMutex,
  writeJsonAtomic
} from './atomic.js'
import { configPath, edvsDir, parseLocalId } from './paths.js'

/**
 * Inserts a new EDV config. The full `config.id` URL must already be
 * assigned by the caller and `config.sequence` must be 0. Runs under the
 * global create lock so the (controller, referenceId) uniqueness scan
 * cannot race with a concurrent create.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.config {IEDVConfig}   the config to insert (with `id`)
 * @returns {Promise<IEDVConfig>} the stored config
 */
export async function insertConfig({
  dataDir,
  config
}: {
  dataDir: string
  config: IEDVConfig
}): Promise<IEDVConfig> {
  const localEdvId = parseLocalId({ id: config.id! })
  return storageMutex.run(createLockKey({ dataDir }), async function insert() {
    if (config.referenceId !== undefined) {
      const existing = await findConfigs({
        dataDir,
        controller: config.controller,
        referenceId: config.referenceId
      })
      if (existing.length > 0) {
        throw new DuplicateError({
          message:
            'Could not create encrypted data vault; ' +
            'duplicate "referenceId" for controller.'
        })
      }
    }
    await writeJsonAtomic({
      filePath: configPath({ dataDir, localEdvId }),
      value: config
    })
    return config
  })
}

/**
 * Gets an EDV config by local vault ID. Throws NotFoundError (404) if the
 * vault does not exist.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.localEdvId {string}
 * @returns {Promise<IEDVConfig>}
 */
export async function getConfig({
  dataDir,
  localEdvId
}: {
  dataDir: string
  localEdvId: string
}): Promise<IEDVConfig> {
  const config = (await readJson({
    filePath: configPath({ dataDir, localEdvId })
  })) as IEDVConfig | null
  if (config === null) {
    throw new NotFoundError({
      message: 'Encrypted data vault configuration not found.'
    })
  }
  return config
}

/**
 * Updates an EDV config. The new sequence must be exactly previous + 1,
 * otherwise InvalidStateError (409). Runs under the vault mutex.
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.config {IEDVConfig}   the full updated config (with `id`)
 * @returns {Promise<IEDVConfig>}
 */
export async function updateConfig({
  dataDir,
  config
}: {
  dataDir: string
  config: IEDVConfig
}): Promise<IEDVConfig> {
  const localEdvId = parseLocalId({ id: config.id! })
  return storageMutex.run(
    edvLockKey({ dataDir, localEdvId }),
    async function update() {
      const existing = await getConfig({ dataDir, localEdvId })
      if (config.sequence !== existing.sequence + 1) {
        throw new InvalidStateError({
          message:
            'Could not update encrypted data vault configuration; ' +
            'unexpected sequence.'
        })
      }
      await writeJsonAtomic({
        filePath: configPath({ dataDir, localEdvId }),
        value: config
      })
      return config
    }
  )
}

/**
 * Finds EDV configs by (controller, referenceId) via a scan of all vault
 * configs. Returns an array of matches (zero or one given the uniqueness
 * invariant).
 *
 * @param options {object}
 * @param options.dataDir {string}
 * @param options.controller {string}
 * @param options.referenceId {string}
 * @returns {Promise<IEDVConfig[]>}
 */
export async function findConfigs({
  dataDir,
  controller,
  referenceId
}: {
  dataDir: string
  controller: string
  referenceId: string
}): Promise<IEDVConfig[]> {
  let entries: string[]
  try {
    entries = await readdir(edvsDir({ dataDir }))
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return []
    }
    throw err
  }
  const matches: IEDVConfig[] = []
  for (const localEdvId of entries.sort()) {
    let config: IEDVConfig | null
    try {
      config = (await readJson({
        filePath: configPath({ dataDir, localEdvId })
      })) as IEDVConfig | null
    } catch {
      // skip directory entries that are not valid vault IDs
      continue
    }
    if (
      config !== null &&
      config.controller === controller &&
      config.referenceId === referenceId
    ) {
      matches.push(config)
    }
  }
  return matches
}
