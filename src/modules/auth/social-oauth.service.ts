import { env } from '../../config/env.js';
import { getRedisStore } from '../../config/redis.js';
import {
  ErrorCode,
  HttpStatus,
  REDIS_PREFIXES,
  SocialProvider,
  TOKEN_LIMITS,
} from '../../constants/index.js';
import { SocialOAuthStateData } from '../../types/index.js';
import { AppError } from '../../utils/app-error.js';
import { generateRandomToken } from '../../utils/crypto.js';
import { computeS256CodeChallenge, generateCodeVerifier } from '../../utils/pkce.js';

export interface VerifiedSocialProfile {
  provider: SocialProvider;
  providerUserId: string;
  email: string;
  emailVerified: boolean;
  name: string;
  preferredUsername: string;
  avatarUrl?: string;
  bio?: string;
  location?: string;
}

interface GoogleTokenResponse {
  access_token?: string;
  error?: string;
  error_description?: string;
}

interface GoogleUserInfoResponse {
  sub?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
}

interface GitHubTokenResponse {
  access_token?: string;
  error?: string;
  error_description?: string;
}

interface GitHubUserResponse {
  id?: number;
  login?: string;
  name?: string | null;
  email?: string | null;
  avatar_url?: string;
  bio?: string | null;
  location?: string | null;
}

interface GitHubEmailItem {
  email: string;
  primary: boolean;
  verified: boolean;
}

export class SocialOAuthService {
  /**
   * Generates a CSRF-resistant `state` + PKCE `code_verifier`, stores in Redis for 10m,
   * and returns the upstream provider authorization URL.
   */
  public async createAuthorizationRedirectUrl(
    provider: SocialProvider,
    authReqId?: string,
  ): Promise<string> {
    const state = generateRandomToken(32);
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = computeS256CodeChallenge(codeVerifier);

    const statePayload: SocialOAuthStateData = {
      provider,
      codeVerifier,
      ...(authReqId ? { authReqId } : {}),
      createdAt: Date.now(),
    };

    const redis = getRedisStore();
    await redis.set(
      `${REDIS_PREFIXES.SOCIAL_STATE}${state}`,
      JSON.stringify(statePayload),
      TOKEN_LIMITS.SOCIAL_STATE_TTL_SECONDS,
    );

    if (provider === SocialProvider.GOOGLE) {
      if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
        throw new AppError(
          'Google OAuth is not configured on this Identity Provider.',
          HttpStatus.SERVICE_UNAVAILABLE,
          ErrorCode.SOCIAL_AUTH_FAILED,
        );
      }

      const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      url.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
      url.searchParams.set('redirect_uri', env.GOOGLE_CALLBACK_URL);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'openid email profile');
      url.searchParams.set('state', state);
      url.searchParams.set('code_challenge', codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');
      url.searchParams.set('prompt', 'select_account');
      return url.toString();
    }

    if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
      throw new AppError(
        'GitHub OAuth is not configured on this Identity Provider.',
        HttpStatus.SERVICE_UNAVAILABLE,
        ErrorCode.SOCIAL_AUTH_FAILED,
      );
    }

    const url = new URL('https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
    url.searchParams.set('redirect_uri', env.GITHUB_CALLBACK_URL);
    url.searchParams.set('scope', 'read:user user:email');
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.toString();
  }

  /**
   * Atomically consumes `state` from Redis (blocking CSRF & replay) and exchanges `code`
   * with upstream provider for verified identity attributes. Never exposes upstream tokens.
   */
  public async verifyCallbackAndFetchProfile(
    expectedProvider: SocialProvider,
    code: string,
    state: string,
  ): Promise<{ profile: VerifiedSocialProfile; authReqId?: string }> {
    const redis = getRedisStore();
    const rawState = await redis.consumeOnce(`${REDIS_PREFIXES.SOCIAL_STATE}${state}`);

    if (!rawState) {
      throw new AppError(
        'Invalid, expired, or already-consumed OAuth state parameter (CSRF check failed).',
        HttpStatus.BAD_REQUEST,
        ErrorCode.INVALID_OAUTH_STATE,
      );
    }

    const storedState = JSON.parse(rawState) as SocialOAuthStateData;
    if (storedState.provider !== expectedProvider) {
      throw new AppError(
        'OAuth state provider mismatch.',
        HttpStatus.BAD_REQUEST,
        ErrorCode.INVALID_OAUTH_STATE,
      );
    }

    const profile =
      expectedProvider === SocialProvider.GOOGLE
        ? await this.exchangeGoogleCode(code, storedState.codeVerifier)
        : await this.exchangeGitHubCode(code, storedState.codeVerifier);

    return {
      profile,
      ...(storedState.authReqId ? { authReqId: storedState.authReqId } : {}),
    };
  }

  private async exchangeGoogleCode(
    code: string,
    codeVerifier: string,
  ): Promise<VerifiedSocialProfile> {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID ?? '',
        client_secret: env.GOOGLE_CLIENT_SECRET ?? '',
        code,
        code_verifier: codeVerifier,
        grant_type: 'authorization_code',
        redirect_uri: env.GOOGLE_CALLBACK_URL,
      }),
    });

    if (!tokenRes.ok) {
      throw new AppError(
        'Failed to exchange authorization code with Google.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.SOCIAL_AUTH_FAILED,
      );
    }

    const tokenData = (await tokenRes.json()) as GoogleTokenResponse;
    if (!tokenData.access_token) {
      throw new AppError(
        'Google did not return a valid access token.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.SOCIAL_AUTH_FAILED,
      );
    }

    const userRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    if (!userRes.ok) {
      throw new AppError(
        'Failed to retrieve verified user profile from Google.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.SOCIAL_AUTH_FAILED,
      );
    }

    const userInfo = (await userRes.json()) as GoogleUserInfoResponse;
    if (!userInfo.sub || !userInfo.email) {
      throw new AppError(
        'Google account did not provide a valid subject ID and email.',
        HttpStatus.BAD_REQUEST,
        ErrorCode.SOCIAL_AUTH_FAILED,
      );
    }

    const emailPrefix = userInfo.email.split('@')[0] ?? 'google_user';

    return {
      provider: SocialProvider.GOOGLE,
      providerUserId: userInfo.sub,
      email: userInfo.email.toLowerCase(),
      emailVerified: Boolean(userInfo.email_verified),
      name: userInfo.name ?? emailPrefix,
      preferredUsername: emailPrefix.replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase() || 'user',
      ...(userInfo.picture ? { avatarUrl: userInfo.picture } : {}),
    };
  }

  private async exchangeGitHubCode(
    code: string,
    codeVerifier: string,
  ): Promise<VerifiedSocialProfile> {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: env.GITHUB_CALLBACK_URL,
        code_verifier: codeVerifier,
      }),
    });

    if (!tokenRes.ok) {
      throw new AppError(
        'Failed to exchange authorization code with GitHub.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.SOCIAL_AUTH_FAILED,
      );
    }

    const tokenData = (await tokenRes.json()) as GitHubTokenResponse;
    if (!tokenData.access_token) {
      throw new AppError(
        'GitHub did not return a valid access token.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.SOCIAL_AUTH_FAILED,
      );
    }

    const commonHeaders = {
      Authorization: `Bearer ${tokenData.access_token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Centralized-IdP-SSO/2.0',
    };

    const [userRes, emailsRes] = await Promise.all([
      fetch('https://api.github.com/user', { headers: commonHeaders }),
      fetch('https://api.github.com/user/emails', { headers: commonHeaders }),
    ]);

    if (!userRes.ok) {
      throw new AppError(
        'Failed to fetch GitHub user profile.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.SOCIAL_AUTH_FAILED,
      );
    }

    const ghUser = (await userRes.json()) as GitHubUserResponse;
    let verifiedEmail: string | undefined;
    let isEmailVerified = false;

    if (emailsRes.ok) {
      const emails = (await emailsRes.json()) as GitHubEmailItem[];
      const primaryVerified = emails.find((e) => e.primary && e.verified);
      const anyVerified = emails.find((e) => e.verified);
      const selected = primaryVerified ?? anyVerified;
      if (selected) {
        verifiedEmail = selected.email.toLowerCase();
        isEmailVerified = true;
      }
    }

    if (!verifiedEmail && ghUser.email) {
      verifiedEmail = ghUser.email.toLowerCase();
    }

    if (!ghUser.id || !ghUser.login || !verifiedEmail) {
      throw new AppError(
        'GitHub account must have at least one verified email address.',
        HttpStatus.BAD_REQUEST,
        ErrorCode.SOCIAL_AUTH_FAILED,
      );
    }

    return {
      provider: SocialProvider.GITHUB,
      providerUserId: String(ghUser.id),
      email: verifiedEmail,
      emailVerified: isEmailVerified,
      name: ghUser.name ?? ghUser.login,
      preferredUsername: ghUser.login.toLowerCase(),
      ...(ghUser.avatar_url ? { avatarUrl: ghUser.avatar_url } : {}),
      ...(ghUser.bio ? { bio: ghUser.bio } : {}),
      ...(ghUser.location ? { location: ghUser.location } : {}),
    };
  }
}
