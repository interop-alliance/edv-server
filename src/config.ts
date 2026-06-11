/**
 * Plugin configuration: the options accepted by `edvPlugin` / `createApp`
 * and the resolved form threaded through the route modules.
 */

export interface EdvPluginOptions {
  /**
   * The public base URL of this server (scheme + host + port, no trailing
   * slash), e.g. `https://edv.example.com`. EDV IDs are full URLs derived
   * from it, and zcap invocation targets / host checks are URL-based, so it
   * must match the URL clients use to reach the server.
   */
  baseUrl: string
  /** Filesystem directory where vault data is stored as plain JSON files. */
  dataDir: string
  /** Route prefix for the EDV API. Defaults to `/edvs`. */
  routePrefix?: string
}

export interface ResolvedEdvOptions {
  baseUrl: string
  dataDir: string
  routePrefix: string
  /** `${baseUrl}${routePrefix}` -- the root invocation target for vault
   * creation and config queries, and the base of every vault URL. */
  edvBaseUrl: string
  /** Host (including port, if any) of `baseUrl`, for zcap host checks. */
  host: string
}

export function resolveOptions({
  baseUrl,
  dataDir,
  routePrefix = '/edvs'
}: EdvPluginOptions): ResolvedEdvOptions {
  if (baseUrl.endsWith('/')) {
    baseUrl = baseUrl.slice(0, -1)
  }
  return {
    baseUrl,
    dataDir,
    routePrefix,
    edvBaseUrl: `${baseUrl}${routePrefix}`,
    host: new URL(baseUrl).host
  }
}
