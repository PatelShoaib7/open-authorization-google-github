import { NextFunction, Request, RequestHandler, Response } from 'express';
import { ZodSchema } from 'zod';
import { ErrorCode, HttpStatus } from '../constants/index.js';
import { AppError } from '../utils/app-error.js';

export interface RequestValidationSchemas {
  body?: ZodSchema;
  query?: ZodSchema;
  params?: ZodSchema;
}

export function validateRequest(schemas: RequestValidationSchemas): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const validationIssues: Array<{ location: string; path: string; message: string }> = [];

    if (schemas.params) {
      const parsed = schemas.params.safeParse(req.params);
      if (!parsed.success) {
        for (const issue of parsed.error.issues) {
          validationIssues.push({
            location: 'params',
            path: issue.path.join('.'),
            message: issue.message,
          });
        }
      } else {
        req.params = parsed.data as Request['params'];
      }
    }

    if (schemas.query) {
      const parsed = schemas.query.safeParse(req.query);
      if (!parsed.success) {
        for (const issue of parsed.error.issues) {
          validationIssues.push({
            location: 'query',
            path: issue.path.join('.'),
            message: issue.message,
          });
        }
      } else {
        req.query = parsed.data as Request['query'];
      }
    }

    if (schemas.body) {
      const parsed = schemas.body.safeParse(req.body);
      if (!parsed.success) {
        for (const issue of parsed.error.issues) {
          validationIssues.push({
            location: 'body',
            path: issue.path.join('.'),
            message: issue.message,
          });
        }
      } else {
        req.body = parsed.data;
      }
    }

    if (validationIssues.length > 0) {
      next(
        new AppError(
          'Request validation failed.',
          HttpStatus.UNPROCESSABLE_ENTITY,
          ErrorCode.VALIDATION_ERROR,
          validationIssues,
        ),
      );
      return;
    }

    next();
  };
}
