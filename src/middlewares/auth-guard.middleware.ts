import { NextFunction, Request, RequestHandler, Response } from 'express';
import { ErrorCode, HttpStatus, UserRole } from '../constants/index.js';
import { AppError } from '../utils/app-error.js';
import { verifyAccessToken } from '../utils/jwt.js';

function extractBearerToken(req: Request): string | null {
  const authHeader = req.header('Authorization');
  if (!authHeader) {
    return null;
  }

  const parts = authHeader.trim().split(/\s+/);
  if (parts.length !== 2 || parts[0]?.toLowerCase() !== 'bearer' || !parts[1]) {
    throw new AppError(
      'Malformed Authorization header. Expected format: Bearer <token>.',
      HttpStatus.UNAUTHORIZED,
      ErrorCode.INVALID_ACCESS_TOKEN,
    );
  }

  return parts[1];
}

export function authGuard(req: Request, _res: Response, next: NextFunction): void {
  try {
    const token = extractBearerToken(req);
    if (!token) {
      throw new AppError(
        'Missing Bearer access token.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.UNAUTHORIZED,
      );
    }

    const claims = verifyAccessToken(token);
    const scopes = claims.scope
      ? claims.scope.split(' ').filter((s) => s.length > 0)
      : [];

    req.user = {
      id: claims.sub,
      roles: Array.isArray(claims.roles) ? claims.roles : [],
      scopes,
      clientId: claims.client_id,
      jti: claims.jti,
    };

    next();
  } catch (err) {
    next(err);
  }
}

export function optionalAuthGuard(req: Request, _res: Response, next: NextFunction): void {
  try {
    const authHeader = req.header('Authorization');
    if (!authHeader) {
      next();
      return;
    }

    const token = extractBearerToken(req);
    if (token) {
      const claims = verifyAccessToken(token);
      req.user = {
        id: claims.sub,
        roles: Array.isArray(claims.roles) ? claims.roles : [],
        scopes: claims.scope ? claims.scope.split(' ').filter((s) => s.length > 0) : [],
        clientId: claims.client_id,
        jti: claims.jti,
      };
    }
    next();
  } catch {
    // Optional guard ignores invalid bearer tokens and treats request as anonymous
    next();
  }
}

export function requireRoles(...allowedRoles: UserRole[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      next(
        new AppError(
          'Authentication required.',
          HttpStatus.UNAUTHORIZED,
          ErrorCode.UNAUTHORIZED,
        ),
      );
      return;
    }

    const hasRole = allowedRoles.some((role) => req.user?.roles.includes(role));
    if (!hasRole) {
      next(
        new AppError(
          `Insufficient role privileges. Required one of: ${allowedRoles.join(', ')}.`,
          HttpStatus.FORBIDDEN,
          ErrorCode.FORBIDDEN,
        ),
      );
      return;
    }

    next();
  };
}

export function requireScopes(...requiredScopes: string[]): RequestHandler {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) {
      next(
        new AppError(
          'Authentication required.',
          HttpStatus.UNAUTHORIZED,
          ErrorCode.UNAUTHORIZED,
        ),
      );
      return;
    }

    // Admins implicitly satisfy management scopes on first-party IdP endpoints
    if (req.user.roles.includes(UserRole.ADMIN)) {
      next();
      return;
    }

    const missingScopes = requiredScopes.filter(
      (scope) => !req.user?.scopes.includes(scope),
    );
    if (missingScopes.length > 0) {
      next(
        new AppError(
          `Access token missing required scope(s): ${missingScopes.join(', ')}.`,
          HttpStatus.FORBIDDEN,
          ErrorCode.INSUFFICIENT_SCOPE,
        ),
      );
      return;
    }

    next();
  };
}
