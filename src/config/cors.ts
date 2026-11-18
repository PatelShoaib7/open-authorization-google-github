import cors, { CorsOptionsDelegate } from 'cors';
import { Request } from 'express';
import {
  ErrorCode,
  HttpStatus,
  REDIS_PREFIXES,
  TOKEN_LIMITS,
} from '../constants/index.js';
import { AppError } from '../utils/app-error.js';
import { logger } from '../utils/logger.js';
import { env } from './env.js';
import { getRedisStore } from './redis.js';

export type AllowedOriginsProvider = () => Promise<string[]>;

let dynamicOriginsProvider: AllowedOriginsProvider | null = null;

export function registerAllowedOriginsProvider(provider: AllowedOriginsProvider): void {
  dynamicOriginsProvider = provider;
}

export function normalizeOrigin(originUrl: string): string {
  const parsed = new URL(originUrl);
  return `${parsed.protocol}//${parsed.host}`.toLowerCase();
}

export async function invalidateCorsOriginsCache(): Promise<void> {
  try {
    const redis = getRedisStore();
    await redis.del(REDIS_PREFIXES.CORS_ORIGINS_CACHE);
  } catch (err) {
    logger.warn('Failed to invalidate CORS origins cache in Redis.', { error: err });
  }
}

async function resolveAllowedOriginsSet(): Promise<Set<string>> {
  const staticOrigins = new Set<string>();
  staticOrigins.add(normalizeOrigin(env.ISSUER_URL));

  for (const origin of env.IDP_ALLOWED_ORIGINS) {
    try {
      staticOrigins.add(normalizeOrigin(origin));
    } catch {
      // Ignore malformed bootstrap origin entries
    }
  }

  if (env.LOGIN_UI_URL) {
    try {
      staticOrigins.add(normalizeOrigin(env.LOGIN_UI_URL));
    } catch {
      // Ignore malformed login UI URL
    }
  }

  if (!dynamicOriginsProvider) {
    return staticOrigins;
  }

  try {
    const redis = getRedisStore();
    const cachedRaw = await redis.get(REDIS_PREFIXES.CORS_ORIGINS_CACHE);
    if (cachedRaw) {
      const cachedList = JSON.parse(cachedRaw) as string[];
      for (const item of cachedList) {
        staticOrigins.add(item);
      }
      return staticOrigins;
    }

    const dbOrigins = await dynamicOriginsProvider();
    const normalizedDbOrigins = dbOrigins.map((o) => normalizeOrigin(o));
    await redis.set(
      REDIS_PREFIXES.CORS_ORIGINS_CACHE,
      JSON.stringify(normalizedDbOrigins),
      TOKEN_LIMITS.CORS_CACHE_TTL_SECONDS,
    );

    for (const item of normalizedDbOrigins) {
      staticOrigins.add(item);
    }
  } catch (err) {
    logger.warn('Dynamic CORS lookup degraded; falling back to static IdP origins.', {
      error: err,
    });
  }

  return staticOrigins;
}

const dynamicCorsDelegate: CorsOptionsDelegate<Request> = async (req, callback) => {
  try {
    // Public OIDC / JWKS discovery endpoints are safe read-only metadata for any Relying Party
    if (req.path.startsWith('/.well-known/')) {
      callback(null, {
        origin: '*',
        methods: ['GET', 'HEAD', 'OPTIONS'],
        credentials: false,
        maxAge: 86400,
      });
      return;
    }

    const requestOrigin = req.header('Origin');

    // Non-browser requests (server-to-server microservices, CLI, native apps) omit Origin
    if (!requestOrigin) {
      callback(null, {
        origin: false,
        credentials: true,
      });
      return;
    }

    let normalizedRequestOrigin: string;
    try {
      normalizedRequestOrigin = normalizeOrigin(requestOrigin);
    } catch {
      callback(
        new AppError(
          'Malformed Origin header.',
          HttpStatus.FORBIDDEN,
          ErrorCode.CORS_ORIGIN_FORBIDDEN,
        ),
      );
      return;
    }

    const allowedOrigins = await resolveAllowedOriginsSet();

    if (!allowedOrigins.has(normalizedRequestOrigin)) {
      callback(
        new AppError(
          `Origin '${requestOrigin}' is not registered with this Identity Provider.`,
          HttpStatus.FORBIDDEN,
          ErrorCode.CORS_ORIGIN_FORBIDDEN,
        ),
      );
      return;
    }

    callback(null, {
      origin: requestOrigin,
      credentials: true,
      methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-Request-Id',
      ],
      exposedHeaders: ['X-Request-Id'],
      maxAge: 600,
    });
  } catch (err) {
    callback(err instanceof Error ? err : new Error('CORS evaluation failed'));
  }
};

export const dynamicCorsMiddleware = cors(dynamicCorsDelegate);
