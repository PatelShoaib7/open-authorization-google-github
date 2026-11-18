export enum UserRole {
  USER = 'user',
  ADMIN = 'admin',
}

export enum OAuthScope {
  OPENID = 'openid',
  PROFILE = 'profile',
  EMAIL = 'email',
  OFFLINE_ACCESS = 'offline_access',
  CLIENTS_READ = 'clients:read',
  CLIENTS_WRITE = 'clients:write',
  USERS_READ = 'users:read',
  USERS_WRITE = 'users:write',
}

export const SUPPORTED_SCOPES: readonly string[] = Object.values(OAuthScope);

export const DEFAULT_CLIENT_SCOPES: readonly string[] = [
  OAuthScope.OPENID,
  OAuthScope.PROFILE,
  OAuthScope.EMAIL,
  OAuthScope.OFFLINE_ACCESS,
];

export enum ApplicationType {
  SPA = 'spa',
  WEB = 'web',
  NATIVE = 'native',
  SERVICE = 'service',
}

export enum SocialProvider {
  GOOGLE = 'google',
  GITHUB = 'github',
}

export const FIRST_PARTY_CLIENT_ID = 'idp-first-party';

export const COOKIE_NAMES = {
  REFRESH_TOKEN: 'idp_refresh_token',
  SSO_SESSION: 'idp_sso_session',
} as const;

export const REDIS_PREFIXES = {
  REFRESH_FAMILY: 'rt:family:',
  USER_FAMILIES: 'rt:user:families:',
  SSO_SESSION: 'sso:session:',
  USER_SSO_SESSIONS: 'sso:user:sessions:',
  OAUTH_AUTH_REQ: 'oauth:req:',
  OAUTH_AUTH_CODE: 'oauth:code:',
  OAUTH_USED_CODE: 'oauth:used_code:',
  SOCIAL_STATE: 'oauth:social_state:',
  CORS_ORIGINS_CACHE: 'cors:allowed_origins',
} as const;

export const TOKEN_LIMITS = {
  OAUTH_AUTH_REQ_TTL_SECONDS: 600, // 10 minutes to complete login + consent
  SOCIAL_STATE_TTL_SECONDS: 600, // 10 minutes to complete Google/GitHub redirect
  USED_CODE_REPLAY_WINDOW_SECONDS: 600, // 10 minutes tracking exchanged auth codes for replay detection
  CORS_CACHE_TTL_SECONDS: 60, // 1 minute Redis cache for registered client origins
  MAX_USED_TOKEN_HASHES_PER_FAMILY: 50,
} as const;
