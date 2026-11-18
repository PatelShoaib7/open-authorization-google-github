import { SocialProvider, UserRole } from '../constants/index.js';

export interface AccessTokenClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  jti: string;
  iat?: number;
  exp?: number;
  scope: string;
  roles: UserRole[];
  client_id: string;
}

export interface IdTokenClaims {
  sub: string;
  iss: string;
  aud: string;
  iat?: number;
  exp?: number;
  nonce?: string;
  name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
}

export interface AuthenticatedUser {
  id: string;
  roles: UserRole[];
  scopes: string[];
  clientId: string;
  jti: string;
}

export interface RefreshTokenFamily {
  familyId: string;
  userId: string;
  clientId: string;
  scope: string;
  currentTokenHash: string;
  usedTokenHashes: string[];
  userAgent?: string;
  ipAddress?: string;
  createdAt: number;
  rotatedAt: number;
  expiresAt: number;
}

export interface SsoSessionData {
  sessionId: string;
  userId: string;
  userAgent?: string;
  ipAddress?: string;
  createdAt: number;
  expiresAt: number;
}

export interface OAuthAuthorizationRequest {
  authReqId: string;
  clientId: string;
  clientName: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  nonce?: string;
  createdAt: number;
}

export interface OAuthAuthorizationCodeData {
  userId: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  nonce?: string;
  createdAt: number;
}

export interface SocialOAuthStateData {
  provider: SocialProvider;
  codeVerifier: string;
  authReqId?: string;
  createdAt: number;
}

export interface JwkRsaPublicKey {
  kty: 'RSA';
  use: 'sig';
  alg: 'RS256';
  kid: string;
  n: string;
  e: string;
}

export interface JwksDocument {
  keys: JwkRsaPublicKey[];
}

export interface RequestMeta {
  ipAddress?: string;
  userAgent?: string;
}
