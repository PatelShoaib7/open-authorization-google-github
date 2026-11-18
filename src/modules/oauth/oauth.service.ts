import { env } from '../../config/env.js';
import { getKeyStore } from '../../config/keys.js';
import { getRedisStore } from '../../config/redis.js';
import {
  DEFAULT_CLIENT_SCOPES,
  ErrorCode,
  HttpStatus,
  OAuthErrorCode,
  OAuthScope,
  REDIS_PREFIXES,
  SUPPORTED_SCOPES,
  TOKEN_LIMITS,
} from '../../constants/index.js';
import {
  JwksDocument,
  OAuthAuthorizationCodeData,
  OAuthAuthorizationRequest,
  RequestMeta,
} from '../../types/index.js';
import { AppError, OAuthProtocolError } from '../../utils/app-error.js';
import {
  generateRandomToken,
  sha256Hex,
  verifySecret,
} from '../../utils/crypto.js';
import { signAccessToken, signIdToken } from '../../utils/jwt.js';
import { logger } from '../../utils/logger.js';
import { isValidPkceString, verifyPkceS256 } from '../../utils/pkce.js';
import { TokenFamilyService } from '../auth/token-family.service.js';
import { OAuthClientEntity } from '../clients/client.model.js';
import { IClientRepository } from '../clients/client.repository.js';
import { IUserRepository } from '../users/user.repository.js';
import { IConsentRepository } from './consent.repository.js';

export interface AuthorizeInputQuery {
  response_type?: string;
  client_id?: string;
  redirect_uri?: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  nonce?: string;
}

export type AuthorizeStepResult =
  | { type: 'REDIRECT_WITH_CODE'; redirectUrl: string }
  | {
      type: 'LOGIN_REQUIRED';
      authReqId: string;
      clientName: string;
      clientId: string;
      scopes: string[];
    }
  | {
      type: 'CONSENT_REQUIRED';
      authReqId: string;
      clientName: string;
      clientId: string;
      userEmail: string;
      scopes: string[];
    };

export interface TokenEndpointInput {
  grantType?: string;
  code?: string;
  redirectUri?: string;
  clientId?: string;
  clientSecret?: string;
  codeVerifier?: string;
  cookieRefreshToken?: string;
  bodyRefreshToken?: string;
  basicAuthHeader?: string;
  meta?: RequestMeta;
}

export interface TokenEndpointResult {
  responseBody: {
    access_token: string;
    token_type: 'Bearer';
    expires_in: number;
    scope: string;
    id_token?: string;
  };
  rawRefreshToken: string;
}

export class OAuthService {
  constructor(
    private readonly clientRepository: IClientRepository,
    private readonly userRepository: IUserRepository,
    private readonly consentRepository: IConsentRepository,
    private readonly tokenFamilyService: TokenFamilyService,
  ) {}

  // ==========================================================================
  // 1. JWKS & OpenID Connect Discovery Metadata
  // ==========================================================================

  public getJwksDocument(): JwksDocument {
    return getKeyStore().jwks;
  }

  public getOpenIdConfiguration(): Record<string, unknown> {
    const issuer = env.ISSUER_URL;
    return {
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      userinfo_endpoint: `${issuer}/api/v1/users/me`,
      revocation_endpoint: `${issuer}/oauth/revoke`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      id_token_signing_alg_values_supported: ['RS256'],
      token_endpoint_auth_methods_supported: [
        'none',
        'client_secret_basic',
        'client_secret_post',
      ],
      scopes_supported: SUPPORTED_SCOPES,
      subject_types_supported: ['public'],
      claims_supported: [
        'sub',
        'iss',
        'aud',
        'exp',
        'iat',
        'name',
        'username',
        'email',
        'email_verified',
        'roles',
        'scope',
      ],
    };
  }

  // ==========================================================================
  // 2. OAuth 2.1 Authorization Endpoint (/oauth/authorize)
  // ==========================================================================

  public async handleAuthorizeRequest(
    query: AuthorizeInputQuery,
    authenticatedUserId?: string,
  ): Promise<AuthorizeStepResult> {
    // STEP 1: Strictly validate client_id and exact redirect_uri BEFORE anything else (Open Redirect prevention)
    if (!query.client_id || query.client_id.trim().length === 0) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_REQUEST,
        'Missing required parameter: client_id.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const client = await this.clientRepository.findByClientId(query.client_id.trim());
    if (!client || !client.isActive) {
      throw new OAuthProtocolError(
        OAuthErrorCode.UNAUTHORIZED_CLIENT,
        'Unknown or inactive client_id.',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!query.redirect_uri || !client.redirectUris.includes(query.redirect_uri)) {
      logger.security('Blocked OAuth authorize attempt with unregistered redirect_uri.', {
        clientId: client.clientId,
        attemptedRedirectUri: query.redirect_uri,
      });
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_REQUEST,
        'Invalid or unregistered redirect_uri. Exact match against registered client redirectUris is required.',
        HttpStatus.BAD_REQUEST,
      );
    }

    // STEP 2: Enforce CSRF state parameter
    if (!query.state || query.state.trim().length < 8 || query.state.length > 512) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_REQUEST,
        'Parameter "state" (minimum 8 characters) is required for CSRF protection.',
        HttpStatus.BAD_REQUEST,
      );
    }

    // STEP 3: Enforce OAuth 2.1 — Explicitly reject deprecated Implicit Grant (`response_type=token`)
    if (
      query.response_type === 'token' ||
      query.response_type === 'id_token' ||
      query.response_type === 'code token'
    ) {
      throw new OAuthProtocolError(
        OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
        'OAuth 2.0 Implicit Grant (response_type=token) is deprecated and disabled under OAuth 2.1. Use response_type=code with PKCE (S256).',
        HttpStatus.BAD_REQUEST,
        query.state,
      );
    }

    if (query.response_type !== 'code') {
      throw new OAuthProtocolError(
        OAuthErrorCode.UNSUPPORTED_RESPONSE_TYPE,
        'Unsupported response_type. Only "code" is supported.',
        HttpStatus.BAD_REQUEST,
        query.state,
      );
    }

    // STEP 4: Enforce mandatory PKCE with S256 for ALL clients (public & confidential)
    if (query.code_challenge_method !== 'S256') {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_REQUEST,
        'PKCE with code_challenge_method=S256 is mandatory under OAuth 2.1 (plain is prohibited).',
        HttpStatus.BAD_REQUEST,
        query.state,
      );
    }

    if (!query.code_challenge || !isValidPkceString(query.code_challenge)) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_REQUEST,
        'Invalid or missing PKCE code_challenge (must conform to RFC 7636: 43-128 base64url chars).',
        HttpStatus.BAD_REQUEST,
        query.state,
      );
    }

    // STEP 5: Validate requested scopes against client's allowedScopes
    const requestedScopes = query.scope
      ? Array.from(
          new Set(
            query.scope
              .trim()
              .split(/\s+/)
              .filter((s) => s.length > 0),
          ),
        )
      : client.allowedScopes.filter((s) => DEFAULT_CLIENT_SCOPES.includes(s));

    if (requestedScopes.length === 0) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_SCOPE,
        'At least one valid scope must be requested.',
        HttpStatus.BAD_REQUEST,
        query.state,
      );
    }

    const disallowedScopes = requestedScopes.filter(
      (s) => !client.allowedScopes.includes(s),
    );
    if (disallowedScopes.length > 0) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_SCOPE,
        `Client is not permitted to request scope(s): ${disallowedScopes.join(', ')}.`,
        HttpStatus.BAD_REQUEST,
        query.state,
      );
    }

    const authRequestData: Omit<OAuthAuthorizationRequest, 'authReqId'> = {
      clientId: client.clientId,
      clientName: client.name,
      redirectUri: query.redirect_uri,
      scope: requestedScopes.join(' '),
      state: query.state,
      codeChallenge: query.code_challenge,
      codeChallengeMethod: 'S256',
      ...(query.nonce ? { nonce: query.nonce } : {}),
      createdAt: Date.now(),
    };

    if (!authenticatedUserId) {
      const authReqId = await this.savePendingAuthRequest(authRequestData);
      return {
        type: 'LOGIN_REQUIRED',
        authReqId,
        clientName: client.name,
        clientId: client.clientId,
        scopes: requestedScopes,
      };
    }

    return this.evaluateConsentOrIssueCode(client, authRequestData, authenticatedUserId);
  }

  public async resumeAuthorizeTransaction(
    authReqId: string,
    authenticatedUserId?: string,
  ): Promise<AuthorizeStepResult> {
    const redis = getRedisStore();
    const rawReq = await redis.get(`${REDIS_PREFIXES.OAUTH_AUTH_REQ}${authReqId}`);
    if (!rawReq) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_REQUEST,
        'Authorization request has expired or is invalid. Please initiate login from the client application again.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const pending = JSON.parse(rawReq) as OAuthAuthorizationRequest;
    const client = await this.clientRepository.findByClientId(pending.clientId);
    if (!client || !client.isActive) {
      await redis.del(`${REDIS_PREFIXES.OAUTH_AUTH_REQ}${authReqId}`);
      throw new OAuthProtocolError(
        OAuthErrorCode.UNAUTHORIZED_CLIENT,
        'Client application is no longer active.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const scopes = pending.scope.split(' ').filter((s) => s.length > 0);
    if (!authenticatedUserId) {
      return {
        type: 'LOGIN_REQUIRED',
        authReqId,
        clientName: client.name,
        clientId: client.clientId,
        scopes,
      };
    }

    const result = await this.evaluateConsentOrIssueCode(
      client,
      pending,
      authenticatedUserId,
      authReqId,
    );

    if (result.type === 'REDIRECT_WITH_CODE') {
      await redis.del(`${REDIS_PREFIXES.OAUTH_AUTH_REQ}${authReqId}`);
    }

    return result;
  }

  public async processConsentDecision(
    authReqId: string,
    decision: 'approve' | 'deny',
    authenticatedUserId: string,
  ): Promise<string> {
    const redis = getRedisStore();
    const rawReq = await redis.consumeOnce(`${REDIS_PREFIXES.OAUTH_AUTH_REQ}${authReqId}`);

    if (!rawReq) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_REQUEST,
        'Authorization request has expired or was already processed.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const pending = JSON.parse(rawReq) as OAuthAuthorizationRequest;
    const client = await this.clientRepository.findByClientId(pending.clientId);
    if (!client || !client.isActive || !client.redirectUris.includes(pending.redirectUri)) {
      throw new OAuthProtocolError(
        OAuthErrorCode.UNAUTHORIZED_CLIENT,
        'Client configuration changed or became inactive.',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (decision === 'deny') {
      const denyUrl = new URL(pending.redirectUri);
      denyUrl.searchParams.set('error', OAuthErrorCode.ACCESS_DENIED);
      denyUrl.searchParams.set('error_description', 'Resource owner denied authorization.');
      denyUrl.searchParams.set('state', pending.state);
      return denyUrl.toString();
    }

    const scopes = pending.scope.split(' ').filter((s) => s.length > 0);
    await this.consentRepository.upsertConsent(
      authenticatedUserId,
      client.clientId,
      scopes,
    );

    return this.issueAuthorizationCodeRedirectUrl(pending, authenticatedUserId);
  }

  // ==========================================================================
  // 3. OAuth 2.1 Token Endpoint (/oauth/token)
  // ==========================================================================

  public async handleTokenRequest(input: TokenEndpointInput): Promise<TokenEndpointResult> {
    // Explicitly block deprecated OAuth 2.0 ROPC (`grant_type=password`) and Implicit grants
    if (input.grantType === 'password') {
      throw new OAuthProtocolError(
        OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
        'Resource Owner Password Credentials (ROPC / grant_type=password) is deprecated and prohibited under OAuth 2.1. Use grant_type=authorization_code with PKCE.',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (input.grantType === 'implicit') {
      throw new OAuthProtocolError(
        OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
        'Implicit grant is deprecated and prohibited under OAuth 2.1.',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (input.grantType === 'authorization_code') {
      return this.exchangeAuthorizationCode(input);
    }

    if (input.grantType === 'refresh_token') {
      return this.exchangeRefreshToken(input);
    }

    throw new OAuthProtocolError(
      OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
      'Unsupported grant_type. Supported values: "authorization_code", "refresh_token".',
      HttpStatus.BAD_REQUEST,
    );
  }

  public async revokeToken(rawRefreshToken?: string): Promise<void> {
    if (!rawRefreshToken) return;
    await this.tokenFamilyService.revokeFamilyByRawToken(rawRefreshToken);
  }

  // ==========================================================================
  // Internal Helpers
  // ==========================================================================

  private async evaluateConsentOrIssueCode(
    client: OAuthClientEntity,
    authReq: Omit<OAuthAuthorizationRequest, 'authReqId'>,
    userId: string,
    existingAuthReqId?: string,
  ): Promise<AuthorizeStepResult> {
    const user = await this.userRepository.findById(userId);
    if (!user || !user.isActive) {
      throw new AppError(
        'Authenticated user is inactive or does not exist.',
        HttpStatus.FORBIDDEN,
        ErrorCode.ACCOUNT_DISABLED,
      );
    }

    const requestedScopes = authReq.scope.split(' ').filter((s) => s.length > 0);

    let hasConsent = !client.requireConsent;
    if (!hasConsent) {
      const existingConsent = await this.consentRepository.findConsent(
        userId,
        client.clientId,
      );
      if (existingConsent) {
        hasConsent = requestedScopes.every((s) =>
          existingConsent.grantedScopes.includes(s),
        );
      }
    }

    if (!hasConsent) {
      const authReqId =
        existingAuthReqId ?? (await this.savePendingAuthRequest(authReq));
      return {
        type: 'CONSENT_REQUIRED',
        authReqId,
        clientName: client.name,
        clientId: client.clientId,
        userEmail: user.email,
        scopes: requestedScopes,
      };
    }

    const redirectUrl = await this.issueAuthorizationCodeRedirectUrl(authReq, userId);
    return {
      type: 'REDIRECT_WITH_CODE',
      redirectUrl,
    };
  }

  private async savePendingAuthRequest(
    data: Omit<OAuthAuthorizationRequest, 'authReqId'>,
  ): Promise<string> {
    const authReqId = generateRandomToken(24);
    const fullReq: OAuthAuthorizationRequest = {
      ...data,
      authReqId,
    };
    const redis = getRedisStore();
    await redis.set(
      `${REDIS_PREFIXES.OAUTH_AUTH_REQ}${authReqId}`,
      JSON.stringify(fullReq),
      TOKEN_LIMITS.OAUTH_AUTH_REQ_TTL_SECONDS,
    );
    return authReqId;
  }

  private async issueAuthorizationCodeRedirectUrl(
    authReq: Omit<OAuthAuthorizationRequest, 'authReqId'>,
    userId: string,
  ): Promise<string> {
    const rawCode = `ac_${generateRandomToken(32)}`;
    const codeHash = sha256Hex(rawCode);

    const codeRecord: OAuthAuthorizationCodeData = {
      userId,
      clientId: authReq.clientId,
      redirectUri: authReq.redirectUri,
      scope: authReq.scope,
      codeChallenge: authReq.codeChallenge,
      codeChallengeMethod: 'S256',
      ...(authReq.nonce ? { nonce: authReq.nonce } : {}),
      createdAt: Date.now(),
    };

    const redis = getRedisStore();
    await redis.set(
      `${REDIS_PREFIXES.OAUTH_AUTH_CODE}${codeHash}`,
      JSON.stringify(codeRecord),
      env.AUTH_CODE_TTL_SECONDS,
    );

    const callbackUrl = new URL(authReq.redirectUri);
    callbackUrl.searchParams.set('code', rawCode);
    callbackUrl.searchParams.set('state', authReq.state);
    return callbackUrl.toString();
  }

  private extractClientCredentials(input: TokenEndpointInput): {
    clientId?: string;
    clientSecret?: string;
  } {
    if (input.basicAuthHeader && input.basicAuthHeader.toLowerCase().startsWith('basic ')) {
      const base64Part = input.basicAuthHeader.slice(6).trim();
      const decoded = Buffer.from(base64Part, 'base64').toString('utf8');
      const colonIdx = decoded.indexOf(':');
      if (colonIdx > 0) {
        return {
          clientId: decodeURIComponent(decoded.slice(0, colonIdx)),
          clientSecret: decodeURIComponent(decoded.slice(colonIdx + 1)),
        };
      }
    }

    return {
      clientId: input.clientId,
      clientSecret: input.clientSecret,
    };
  }

  private async authenticateClient(input: TokenEndpointInput): Promise<OAuthClientEntity> {
    const { clientId, clientSecret } = this.extractClientCredentials(input);
    if (!clientId) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_CLIENT,
        'Missing client_id.',
        HttpStatus.UNAUTHORIZED,
      );
    }

    const client = await this.clientRepository.findByClientId(clientId, true);
    if (!client || !client.isActive) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_CLIENT,
        'Invalid or inactive client.',
        HttpStatus.UNAUTHORIZED,
      );
    }

    if (client.isConfidential) {
      if (!clientSecret || !client.clientSecretHash) {
        throw new OAuthProtocolError(
          OAuthErrorCode.INVALID_CLIENT,
          'Confidential client authentication requires a valid client_secret.',
          HttpStatus.UNAUTHORIZED,
        );
      }

      const validSecret = await verifySecret(client.clientSecretHash, clientSecret);
      if (!validSecret) {
        throw new OAuthProtocolError(
          OAuthErrorCode.INVALID_CLIENT,
          'Client secret authentication failed.',
          HttpStatus.UNAUTHORIZED,
        );
      }
    }

    return client;
  }

  private async exchangeAuthorizationCode(
    input: TokenEndpointInput,
  ): Promise<TokenEndpointResult> {
    const client = await this.authenticateClient(input);

    if (!input.code || !input.redirectUri || !input.codeVerifier) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_REQUEST,
        'Parameters "code", "redirect_uri", and "code_verifier" are required for authorization_code grant.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const redis = getRedisStore();
    const codeHash = sha256Hex(input.code);

    // OAuth 2.1 / RFC 6749 Section 10.5: Detect replay of an already-exchanged authorization code
    const previouslyIssuedFamilyId = await redis.get(
      `${REDIS_PREFIXES.OAUTH_USED_CODE}${codeHash}`,
    );
    if (previouslyIssuedFamilyId) {
      await this.tokenFamilyService.revokeFamilyById(previouslyIssuedFamilyId);
      logger.security(
        'AUTHORIZATION_CODE_REPLAY_DETECTED: Replayed authorization code detected. Revoked associated token family.',
        {
          clientId: client.clientId,
          revokedFamilyId: previouslyIssuedFamilyId,
        },
      );
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'Authorization code has already been used. Associated session tokens have been revoked.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const rawCodeData = await redis.consumeOnce(
      `${REDIS_PREFIXES.OAUTH_AUTH_CODE}${codeHash}`,
    );
    if (!rawCodeData) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'Invalid or expired authorization code.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const codeData = JSON.parse(rawCodeData) as OAuthAuthorizationCodeData;

    if (codeData.clientId !== client.clientId) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'Authorization code was not issued to this client_id.',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (codeData.redirectUri !== input.redirectUri) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'redirect_uri does not match the URI used during authorization.',
        HttpStatus.BAD_REQUEST,
      );
    }

    // Verify PKCE S256 challenge in constant time
    const isPkceValid = verifyPkceS256(input.codeVerifier, codeData.codeChallenge);
    if (!isPkceValid) {
      logger.security('PKCE S256 verification failed on /oauth/token.', {
        clientId: client.clientId,
      });
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'PKCE code_verifier verification failed.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const user = await this.userRepository.findById(codeData.userId);
    if (!user || !user.isActive) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'User account is disabled or no longer exists.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const grantedScopes = codeData.scope.split(' ').filter((s) => s.length > 0);
    const { accessToken, expiresIn } = signAccessToken({
      userId: user.id,
      clientId: client.clientId,
      roles: user.roles,
      scopes: grantedScopes,
    });

    const { rawRefreshToken, family } =
      await this.tokenFamilyService.issueRefreshTokenFamily({
        userId: user.id,
        clientId: client.clientId,
        scope: codeData.scope,
        meta: input.meta,
      });

    // Record exchanged code -> familyId mapping to detect authorization code replay
    await redis.set(
      `${REDIS_PREFIXES.OAUTH_USED_CODE}${codeHash}`,
      family.familyId,
      TOKEN_LIMITS.USED_CODE_REPLAY_WINDOW_SECONDS,
    );

    const includeIdToken = grantedScopes.includes(OAuthScope.OPENID);
    const idToken = includeIdToken
      ? signIdToken({
          userId: user.id,
          clientId: client.clientId,
          ...(codeData.nonce ? { nonce: codeData.nonce } : {}),
          ...(grantedScopes.includes(OAuthScope.PROFILE)
            ? {
                name: user.name,
                ...(user.avatarUrl ? { picture: user.avatarUrl } : {}),
              }
            : {}),
          ...(grantedScopes.includes(OAuthScope.EMAIL)
            ? {
                email: user.email,
                emailVerified: user.emailVerified,
              }
            : {}),
        })
      : undefined;

    return {
      responseBody: {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: expiresIn,
        scope: codeData.scope,
        ...(idToken ? { id_token: idToken } : {}),
      },
      rawRefreshToken,
    };
  }

  private async exchangeRefreshToken(
    input: TokenEndpointInput,
  ): Promise<TokenEndpointResult> {
    const client = await this.authenticateClient(input);

    // Browser/SPA clients strictly transmit refresh tokens via HttpOnly cookies;
    // confidential backend services may pass cookie or body refresh_token
    const incomingRawToken =
      input.cookieRefreshToken ??
      (client.isConfidential ? input.bodyRefreshToken : undefined);

    if (!incomingRawToken) {
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'Missing refresh token (must be sent via HttpOnly cookie).',
        HttpStatus.BAD_REQUEST,
      );
    }

    let rotated: { newRawRefreshToken: string; family: { familyId: string; userId: string; clientId: string; scope: string } };
    try {
      rotated = await this.tokenFamilyService.rotateRefreshToken(incomingRawToken);
    } catch (err) {
      if (
        err instanceof AppError &&
        err.code === ErrorCode.REFRESH_TOKEN_REUSE_DETECTED
      ) {
        throw new OAuthProtocolError(
          OAuthErrorCode.INVALID_GRANT,
          'Refresh token reuse detected. Entire token family has been revoked.',
          HttpStatus.BAD_REQUEST,
        );
      }
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'Invalid or expired refresh token.',
        HttpStatus.BAD_REQUEST,
      );
    }

    // Prevent cross-client refresh token confusion
    if (rotated.family.clientId !== client.clientId) {
      await this.tokenFamilyService.revokeFamilyById(rotated.family.familyId);
      logger.security(
        'CROSS_CLIENT_REFRESH_ATTEMPT: Client attempted to rotate a refresh token belonging to another client. Family revoked.',
        {
          expectedClientId: rotated.family.clientId,
          actualClientId: client.clientId,
        },
      );
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'Refresh token does not belong to this client_id.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const user = await this.userRepository.findById(rotated.family.userId);
    if (!user || !user.isActive) {
      await this.tokenFamilyService.revokeFamilyById(rotated.family.familyId);
      throw new OAuthProtocolError(
        OAuthErrorCode.INVALID_GRANT,
        'User account is disabled or deleted.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const grantedScopes = rotated.family.scope.split(' ').filter((s) => s.length > 0);
    const { accessToken, expiresIn } = signAccessToken({
      userId: user.id,
      clientId: client.clientId,
      roles: user.roles,
      scopes: grantedScopes,
    });

    return {
      responseBody: {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: expiresIn,
        scope: rotated.family.scope,
      },
      rawRefreshToken: rotated.newRawRefreshToken,
    };
  }
}
