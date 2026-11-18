import { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';
import { env } from '../config/env.js';
import { ErrorCode, HttpStatus } from '../constants/index.js';
import { AppError, OAuthProtocolError } from '../utils/app-error.js';
import { logger } from '../utils/logger.js';

interface MongoDuplicateKeyError extends Error {
  code?: number;
  keyValue?: Record<string, unknown>;
}

export function notFoundHandler(req: Request, _res: Response, next: NextFunction): void {
  next(
    new AppError(
      `Route '${req.method} ${req.originalUrl}' not found on Identity Provider.`,
      HttpStatus.NOT_FOUND,
      ErrorCode.RESOURCE_NOT_FOUND,
    ),
  );
}

export function globalErrorHandler(
  err: unknown,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  // RFC 6749 Section 5.2 OAuth 2.1 protocol error format
  if (err instanceof OAuthProtocolError) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.status(err.statusCode).json({
      error: err.oauthError,
      error_description: err.errorDescription,
      ...(err.state ? { state: err.state } : {}),
    });
    return;
  }

  if (err instanceof AppError) {
    res.status(err.statusCode).json({
      success: false,
      error: {
        code: err.code,
        message: err.message,
        ...(err.details !== undefined ? { details: err.details } : {}),
        requestId: req.requestId,
      },
    });
    return;
  }

  if (err instanceof ZodError) {
    res.status(HttpStatus.UNPROCESSABLE_ENTITY).json({
      success: false,
      error: {
        code: ErrorCode.VALIDATION_ERROR,
        message: 'Validation error.',
        details: err.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
        requestId: req.requestId,
      },
    });
    return;
  }

  // Handle MongoDB E11000 duplicate key constraint violations cleanly
  if (
    err instanceof Error &&
    'code' in err &&
    (err as MongoDuplicateKeyError).code === 11000
  ) {
    const duplicateFields = Object.keys((err as MongoDuplicateKeyError).keyValue ?? {});
    res.status(HttpStatus.CONFLICT).json({
      success: false,
      error: {
        code: ErrorCode.DUPLICATE_RESOURCE,
        message:
          duplicateFields.length > 0
            ? `A record with that ${duplicateFields.join(', ')} already exists.`
            : 'Duplicate resource conflict.',
        requestId: req.requestId,
      },
    });
    return;
  }

  logger.error('Unhandled exception in request pipeline.', {
    requestId: req.requestId,
    method: req.method,
    path: req.originalUrl,
    error: err,
  });

  res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
    success: false,
    error: {
      code: ErrorCode.INTERNAL_ERROR,
      message:
        env.NODE_ENV === 'production'
          ? 'An unexpected internal error occurred.'
          : err instanceof Error
            ? err.message
            : 'Unknown error',
      requestId: req.requestId,
    },
  });
}
