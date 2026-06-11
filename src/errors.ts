/**
 * Error types for the EDV server. Each error carries a public `name` and
 * `httpStatusCode`; the fastify error handler (registered in plugin.ts)
 * serializes them as `{name, message}` JSON with the matching status code.
 * Clients (notably @interop/edv-client) rely only on the HTTP status codes:
 * 400, 403, 404, 409.
 */

export interface EdvErrorOptions {
  message: string
  name?: string
  httpStatusCode?: number
  cause?: Error
}

export class EdvError extends Error {
  httpStatusCode: number

  constructor({ message, name, httpStatusCode = 500, cause }: EdvErrorOptions) {
    super(message, cause ? { cause } : undefined)
    this.name = name ?? new.target.name
    this.httpStatusCode = httpStatusCode
  }
}

/** A resource (vault, document, or chunk) was not found. 404. */
export class NotFoundError extends EdvError {
  constructor({ message, cause }: { message: string; cause?: Error }) {
    super({ message, name: 'NotFoundError', httpStatusCode: 404, cause })
  }
}

/** An insert would duplicate an existing resource or unique attribute. 409. */
export class DuplicateError extends EdvError {
  constructor({ message, cause }: { message: string; cause?: Error }) {
    super({ message, name: 'DuplicateError', httpStatusCode: 409, cause })
  }
}

/** An update was made against a stale sequence number. 409. */
export class InvalidStateError extends EdvError {
  constructor({ message, cause }: { message: string; cause?: Error }) {
    super({ message, name: 'InvalidStateError', httpStatusCode: 409, cause })
  }
}

/** Authorization failed. 403. */
export class NotAllowedError extends EdvError {
  constructor({
    message,
    httpStatusCode = 403,
    cause
  }: {
    message: string
    httpStatusCode?: number
    cause?: Error
  }) {
    super({ message, name: 'NotAllowedError', httpStatusCode, cause })
  }
}

/** The request data is malformed or inconsistent. 400. */
export class DataError extends EdvError {
  constructor({ message, cause }: { message: string; cause?: Error }) {
    super({ message, name: 'DataError', httpStatusCode: 400, cause })
  }
}
