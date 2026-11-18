import { CookieOptions, Response } from 'express';
import { env } from '../config/env.js';
import { COOKIE_NAMES } from '../constants/index.js';

function buildBaseCookieOptions(maxAgeMs?: number): CookieOptions {
  return {
    httpOnly: true,
    secure: env.COOKIE_SECURE,
    sameSite: env.COOKIE_SAME_SITE,
    path: '/',
    ...(env.COOKIE_DOMAIN ? { domain: env.COOKIE_DOMAIN } : {}),
    ...(maxAgeMs !== undefined ? { maxAge: maxAgeMs } : {}),
  };
}

export function setRefreshTokenCookie(res: Response, rawRefreshToken: string): void {
  const maxAgeMs = env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000;
  res.cookie(COOKIE_NAMES.REFRESH_TOKEN, rawRefreshToken, buildBaseCookieOptions(maxAgeMs));
}

export function clearRefreshTokenCookie(res: Response): void {
  res.clearCookie(COOKIE_NAMES.REFRESH_TOKEN, buildBaseCookieOptions());
}

export function setSsoSessionCookie(res: Response, sessionId: string): void {
  const maxAgeMs = env.SSO_SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;
  // SameSite=Lax is required on SSO browser session cookies so top-level GET redirects to /oauth/authorize include the SSO session
  res.cookie(COOKIE_NAMES.SSO_SESSION, sessionId, {
    ...buildBaseCookieOptions(maxAgeMs),
    sameSite: 'lax',
  });
}

export function clearSsoSessionCookie(res: Response): void {
  res.clearCookie(COOKIE_NAMES.SSO_SESSION, {
    ...buildBaseCookieOptions(),
    sameSite: 'lax',
  });
}
