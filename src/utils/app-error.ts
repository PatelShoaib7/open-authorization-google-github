import { ErrorCode, HttpStatus, HttpStatusCode, OAuthErrorCode } from '../constants/index.js';

export class AppError extends Error {
  public readonly statusCode: HttpStatusCode;
  public readonly code: ErrorCode;
  public readonly details?: unknown;
  public readonly isOperational: boolean;

  constructor(
    message: string,
    statusCode: HttpStatusCode = HttpStatus.INTERNAL_SERVER_ERROR,
    code: ErrorCode = ErrorCode.INTERNAL_ERROR,
    details?: unknown,
  ) {
    super(message);
    this.name = 'AppError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * RFC 6749 Section 5.2 / Section 4.1.2.1 compliant OAuth 2.1 protocol error.
 * Serializes as `{ error: "<oauth_code>", error_description: "<message>" }`.
 */
export class OAuthProtocolError extends Error {
  public readonly statusCode: HttpStatusCode;
  public readonly oauthError: OAuthErrorCode;
  public readonly errorDescription: string;
  public readonly state?: string;

  constructor(
    oauthError: OAuthErrorCode,
    errorDescription: string,
    statusCode: HttpStatusCode = HttpStatus.BAD_REQUEST,
    state?: string,
  ) {
    super(errorDescription);
    this.name = 'OAuthProtocolError';
    this.oauthError = oauthError;
    this.errorDescription = errorDescription;
    this.statusCode = statusCode;
    this.state = state;
    Error.captureStackTrace(this, this.constructor);
  }
}
