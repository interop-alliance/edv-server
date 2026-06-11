/**
 * Filesystem primitives for the storage layer: atomic pretty-printed JSON
 * writes (tmp file + rename) and a keyed in-process mutex that serializes
 * writes per vault.
 *
 * Note: writes are atomic (rename) but not durable (no fsync) -- this is a
 * development-server tradeoff, documented in the README.
 */
import { randomBytes } from 'node:crypto'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import * as path from 'node:path'

/**
 * Serializes async functions per key. `run` chains the given function onto
 * the tail of the key's promise queue, so all functions for the same key
 * execute strictly one at a time, in call order.
 */
export class KeyedMutex {
  private readonly queues = new Map<string, Promise<unknown>>()

  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.queues.get(key) ?? Promise.resolve()
    const next = previous.then(fn, fn)
    // keep the chain alive even if `fn` rejects
    this.queues.set(
      key,
      next.catch(() => {})
    )
    try {
      return await next
    } finally {
      if (this.queues.get(key) === next) {
        this.queues.delete(key)
      }
    }
  }
}

/**
 * The shared storage mutex. Write paths lock on a per-vault key
 * (`edv:<dataDir>:<localEdvId>`); vault creation locks on a global
 * per-data-dir key (`create:<dataDir>`) so referenceId uniqueness scans
 * cannot race.
 */
export const storageMutex = new KeyedMutex()

export function edvLockKey({
  dataDir,
  localEdvId
}: {
  dataDir: string
  localEdvId: string
}): string {
  return `edv:${dataDir}:${localEdvId}`
}

export function createLockKey({ dataDir }: { dataDir: string }): string {
  return `create:${dataDir}`
}

/**
 * Writes a value as pretty-printed (2-space) JSON, atomically: the value is
 * written to a temp file in the same directory, then renamed into place.
 * Parent directories are created as needed.
 *
 * @param options {object}
 * @param options.filePath {string}   the destination path
 * @param options.value {unknown}   the value to serialize
 * @returns {Promise<void>}
 */
export async function writeJsonAtomic({
  filePath,
  value
}: {
  filePath: string
  value: unknown
}): Promise<void> {
  const dir = path.dirname(filePath)
  await mkdir(dir, { recursive: true })
  const tmpPath = path.join(dir, `.tmp-${randomBytes(8).toString('hex')}.json`)
  await writeFile(tmpPath, JSON.stringify(value, null, 2) + '\n', 'utf8')
  await rename(tmpPath, filePath)
}

/**
 * Reads and parses a JSON file. Returns `null` if the file does not exist.
 *
 * @param options {object}
 * @param options.filePath {string}   the path to read
 * @returns {Promise<unknown|null>}
 */
export async function readJson({
  filePath
}: {
  filePath: string
}): Promise<unknown | null> {
  try {
    const text = await readFile(filePath, 'utf8')
    return JSON.parse(text)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return null
    }
    throw err
  }
}
