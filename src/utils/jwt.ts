import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import { getKeyStore } from '../config/keys.js';
import { ErrorCode, HttpStatus, UserRole } from '../constants/index.js';
import { AccessTokenClaims, IdTokenClaims } from '../types/index.js';
import { AppError } from './app-error.js';

export interface SignAccessTokenParams {
  userId: string;
  clientId: string;
  roles: UserRole[];
  scopes: string[];
}

export interface SignIdTokenParams {
  userId: string;
  clientId: string;
  nonce?: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  picture?: string;
}

/**
 * Signs a short-lived (15m) OAuth 2.1 Access Token using asymmetric RS256 and embeds `kid` in JWT header.
 */
export function signAccessToken(params: SignAccessTokenParams): {
  accessToken: string;
  expiresIn: number;
  jti: string;
} {
  const { active } = getKeyStore();
  const jti = crypto.randomUUID();
  const audience =
    params.clientId === env.ISSUER_URL
      ? env.ISSUER_URL
      : [env.ISSUER_URL, params.clientId];

  const payload: Omit<AccessTokenClaims, 'iat' | 'exp'> = {
    sub: params.userId,
    iss: env.ISSUER_URL,
    aud: audience,
    jti,
    scope: params.scopes.join(' '),
    roles: params.roles,
    client_id: params.clientId,
  };

  const accessToken = jwt.sign(payload, active.privateKeyPem, {
    algorithm: 'RS256',
    keyid: active.kid,
    expiresIn: env.ACCESS_TOKEN_TTL_SECONDS,
  });

  return {
    accessToken,
    expiresIn: env.ACCESS_TOKEN_TTL_SECONDS,
    jti,
  };
}

/**
 * Signs an OpenID Connect ID Token with RS256 when `openid` scope is requested.
 */
export function signIdToken(params: SignIdTokenParams): string {
  const { active } = getKeyStore();

  const payload: Omit<IdTokenClaims, 'iat' | 'exp'> = {
    sub: params.userId,
    iss: env.ISSUER_URL,
    aud: params.clientId,
    ...(params.nonce ? { nonce: params.nonce } : {}),
    ...(params.name ? { name: params.name } : {}),
    ...(params.email ? { email: params.email } : {}),
    ...(params.emailVerified !== undefined ? { email_verified: params.emailVerified } : {}),
    ...(params.picture ? { picture: params.picture } : {}),
  };

  return jwt.sign(payload, active.privateKeyPem, {
    algorithm: 'RS256',
    keyid: active.kid,
    expiresIn: env.ACCESS_TOKEN_TTL_SECONDS,
  });
}

/**
 * Strictly verifies an RS256 Access Token against the IdP's JWKS key store.
 * Defends against `alg: none`, `HS256` algorithm confusion, and unknown `kid` headers.
 */
export function verifyAccessToken(token: string, expectedAudience?: string): AccessTokenClaims {
  const decodedComplete = jwt.decode(token, { complete: true });

  if (!decodedComplete || typeof decodedComplete !== 'object') {
    throw new AppError(
      'Malformed access token.',
      HttpStatus.UNAUTHORIZED,
      ErrorCode.INVALID_ACCESS_TOKEN,
    );
  }

  const { header } = decodedComplete;
  if (header.alg !== 'RS256' || !header.kid) {
    throw new AppError(
      'Unsupported signing algorithm or missing key identifier (kid). RS256 is strictly required.',
      HttpStatus.UNAUTHORIZED,
      ErrorCode.INVALID_ACCESS_TOKEN,
    );
  }

  const { verificationKeysByKid } = getKeyStore();
  const verificationKey = verificationKeysByKid.get(header.kid);

  if (!verificationKey) {
    throw new AppError(
      'Signing key (kid) is not recognized by this Identity Provider.',
      HttpStatus.UNAUTHORIZED,
      ErrorCode.INVALID_ACCESS_TOKEN,
    );
  }

  try {
    const verified = jwt.verify(token, verificationKey, {
      algorithms: ['RS256'],
      issuer: env.ISSUER_URL,
      ...(expectedAudience ? { audience: expectedAudience } : {}),
    });

    if (!verified || typeof verified !== 'object' || !('sub' in verified)) {
      throw new AppError(
        'Invalid access token claims.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.INVALID_ACCESS_TOKEN,
      );
    }

    return verified as AccessTokenClaims;
  } catch (err) {
    if (err instanceof AppError) {
      throw err;
    }
    if (err instanceof jwt.TokenExpiredError) {
      throw new AppError(
        'Access token has expired.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.EXPIRED_ACCESS_TOKEN,
      );
    }
    throw new AppError(
      'Access token signature or claims verification failed.',
      HttpStatus.UNAUTHORIZED,
      ErrorCode.INVALID_ACCESS_TOKEN,
    );
  }
}
