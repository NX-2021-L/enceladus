export class SessionExpiredError extends Error {
  readonly status: number

  constructor(message = 'Session expired', status = 401) {
    super(message)
    this.name = 'SessionExpiredError'
    this.status = status
  }
}

export function isSessionExpiredError(error: unknown): error is SessionExpiredError {
  return error instanceof SessionExpiredError
}
