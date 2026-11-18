import crypto from 'node:crypto';
import { NextFunction, Request, Response } from 'express';

export function requestContextMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const incomingId = req.header('X-Request-Id');
  const requestId =
    incomingId && /^[A-Za-z0-9\-_]{8,64}$/.test(incomingId)
      ? incomingId
      : crypto.randomUUID();

  req.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  next();
}
