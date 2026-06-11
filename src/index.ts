/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
export { edvPlugin, createApp } from './plugin.js'
export type { EdvPluginOptions, ResolvedEdvOptions } from './config.js'
export {
  EdvError,
  NotFoundError,
  DuplicateError,
  InvalidStateError,
  NotAllowedError,
  DataError
} from './errors.js'
export { generateLocalId, assert128BitId } from './helpers.js'
export * as schemas from './schemas.js'
export type { EdvRequestContext } from './http/edv-context.js'
