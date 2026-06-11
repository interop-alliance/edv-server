/**
 * Standalone server entry point. Environment configuration:
 * - PORT          (default 5000)
 * - EDV_BASE_URL  (default `http://localhost:<PORT>`)
 * - EDV_DATA_DIR  (default `./data`)
 * - EDV_ROUTE_PREFIX (default `/edvs`)
 */
import { createApp } from './plugin.js'

const port = Number(process.env.PORT ?? 5000)
const baseUrl = process.env.EDV_BASE_URL ?? `http://localhost:${port}`
const dataDir = process.env.EDV_DATA_DIR ?? './data'
const routePrefix = process.env.EDV_ROUTE_PREFIX ?? '/edvs'

const app = createApp({
  baseUrl,
  dataDir,
  routePrefix,
  fastifyOptions: { logger: true }
})

try {
  await app.listen({ port, host: '0.0.0.0' })
  app.log.info(`EDV server: ${baseUrl}${routePrefix} (data dir: ${dataDir})`)
} catch (err) {
  app.log.error(err)
  process.exit(1)
}
