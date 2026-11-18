import { Request, Response } from 'express';
import { env } from '../../config/env.js';
import {
  COOKIE_NAMES,
  ErrorCode,
  HttpStatus,
} from '../../constants/index.js';
import { AppError } from '../../utils/app-error.js';
import { asyncHandler } from '../../utils/async-handler.js';
import {
  clearRefreshTokenCookie,
  setRefreshTokenCookie,
} from '../../utils/cookies.js';
import { TokenFamilyService } from '../auth/token-family.service.js';
import {
  renderConsentScreenHtml,
  renderSsoLoginHtml,
} from './oauth-ui.templates.js';
import { AuthorizeStepResult, OAuthService } from './oauth.service.js';

export class OAuthController {
  constructor(
    private readonly oauthService: OAuthService,
    private readonly tokenFamilyService: TokenFamilyService,
  ) {}

  public readonly jwks = asyncHandler(async (_req: Request, res: Response) => {
    const jwks = this.oauthService.getJwksDocument();
    res.setHeader('Cache-Control', 'public, max-age=3600, must-revalidate');
    res.status(HttpStatus.OK).json(jwks);
  });

  public readonly openIdConfiguration = asyncHandler(
    async (_req: Request, res: Response) => {
      const metadata = this.oauthService.getOpenIdConfiguration();
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.status(HttpStatus.OK).json(metadata);
    },
  );

  public readonly authorize = asyncHandler(async (req: Request, res: Response) => {
    const authenticatedUserId = await this.resolveAuthenticatedUserId(req);
    const step = await this.oauthService.handleAuthorizeRequest(
      {
        response_type: req.query.response_type as string | undefined,
        client_id: req.query.client_id as string | undefined,
        redirect_uri: req.query.redirect_uri as string | undefined,
        scope: req.query.scope as string | undefined,
        state: req.query.state as string | undefined,
        code_challenge: req.query.code_challenge as string | undefined,
        code_challenge_method: req.query.code_challenge_method as string | undefined,
        nonce: req.query.nonce as string | undefined,
      },
      authenticatedUserId,
    );

    this.dispatchAuthorizeStep(req, res, step);
  });

  public readonly resumeAuthorize = asyncHandler(
    async (req: Request, res: Response) => {
      const authReqId = req.query.auth_req_id as string;
      const authenticatedUserId = await this.resolveAuthenticatedUserId(req);
      const step = await this.oauthService.resumeAuthorizeTransaction(
        authReqId,
        authenticatedUserId,
      );

      this.dispatchAuthorizeStep(req, res, step);
    },
  );

  public readonly submitConsentDecision = asyncHandler(
    async (req: Request, res: Response) => {
      const authenticatedUserId = await this.resolveAuthenticatedUserId(req);
      if (!authenticatedUserId) {
        throw new AppError(
          'Active SSO session or Bearer token is required to submit authorization consent.',
          HttpStatus.UNAUTHORIZED,
          ErrorCode.UNAUTHORIZED,
        );
      }

      const { auth_req_id, decision } = req.body as {
        auth_req_id: string;
        decision: 'approve' | 'deny';
      };

      const redirectUrl = await this.oauthService.processConsentDecision(
        auth_req_id,
        decision,
        authenticatedUserId,
      );

      const prefersJson =
        (req.header('Accept') ?? '').includes('application/json') &&
        !(req.header('Accept') ?? '').includes('text/html');

      if (prefersJson) {
        res.status(HttpStatus.OK).json({
          success: true,
          data: { redirectUrl },
        });
        return;
      }

      res.redirect(HttpStatus.FOUND, redirectUrl);
    },
  );

  public readonly token = asyncHandler(async (req: Request, res: Response) => {
    const cookieRefreshToken = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN] as
      | string
      | undefined;

    try {
      const result = await this.oauthService.handleTokenRequest({
        grantType: req.body?.grant_type as string | undefined,
        code: req.body?.code as string | undefined,
        redirectUri: req.body?.redirect_uri as string | undefined,
        clientId: req.body?.client_id as string | undefined,
        clientSecret: req.body?.client_secret as string | undefined,
        codeVerifier: req.body?.code_verifier as string | undefined,
        bodyRefreshToken: req.body?.refresh_token as string | undefined,
        cookieRefreshToken,
        basicAuthHeader: req.header('Authorization'),
        meta: {
          ipAddress: req.ip,
          userAgent: req.header('User-Agent'),
        },
      });

      setRefreshTokenCookie(res, result.rawRefreshToken);

      // RFC 6749 Section 5.1 mandatory caching headers
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');

      res.status(HttpStatus.OK).json(result.responseBody);
    } catch (err) {
      if (req.body?.grant_type === 'refresh_token') {
        clearRefreshTokenCookie(res);
      }
      throw err;
    }
  });

  public readonly revoke = asyncHandler(async (req: Request, res: Response) => {
    const rawToken =
      (req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN] as string | undefined) ??
      (req.body?.token as string | undefined);

    await this.oauthService.revokeToken(rawToken);
    clearRefreshTokenCookie(res);

    res.status(HttpStatus.OK).json({
      success: true,
      message: 'Token revoked.',
    });
  });

  private async resolveAuthenticatedUserId(req: Request): Promise<string | undefined> {
    if (req.user?.id) {
      return req.user.id;
    }

    const ssoCookie = req.cookies?.[COOKIE_NAMES.SSO_SESSION] as string | undefined;
    if (ssoCookie) {
      const ssoSession = await this.tokenFamilyService.resolveSsoSession(ssoCookie);
      if (ssoSession) {
        return ssoSession.userId;
      }
    }

    return undefined;
  }

  private dispatchAuthorizeStep(
    req: Request,
    res: Response,
    step: AuthorizeStepResult,
  ): void {
    res.setHeader('Cache-Control', 'no-store');

    if (step.type === 'REDIRECT_WITH_CODE') {
      res.redirect(HttpStatus.FOUND, step.redirectUrl);
      return;
    }

    const prefersJson =
      (req.header('Accept') ?? '').includes('application/json') &&
      !(req.header('Accept') ?? '').includes('text/html');

    if (step.type === 'LOGIN_REQUIRED') {
      if (env.LOGIN_UI_URL) {
        const loginUrl = new URL(env.LOGIN_UI_URL);
        loginUrl.searchParams.set('auth_req_id', step.authReqId);
        res.redirect(HttpStatus.FOUND, loginUrl.toString());
        return;
      }

      if (prefersJson) {
        res.status(HttpStatus.OK).json({
          status: 'login_required',
          authReqId: step.authReqId,
          client: {
            clientId: step.clientId,
            name: step.clientName,
          },
          requestedScopes: step.scopes,
          loginEndpoint: '/api/v1/auth/login',
        });
        return;
      }

      res
        .status(HttpStatus.OK)
        .type('html')
        .send(
          renderSsoLoginHtml({
            authReqId: step.authReqId,
            clientName: step.clientName,
          }),
        );
      return;
    }

    if (prefersJson) {
      res.status(HttpStatus.OK).json({
        status: 'consent_required',
        authReqId: step.authReqId,
        client: {
          clientId: step.clientId,
          name: step.clientName,
        },
        userEmail: step.userEmail,
        requestedScopes: step.scopes,
        decisionEndpoint: '/oauth/authorize/decision',
      });
      return;
    }

    res
      .status(HttpStatus.OK)
      .type('html')
      .send(
        renderConsentScreenHtml({
          authReqId: step.authReqId,
          clientName: step.clientName,
          userEmail: step.userEmail,
          scopes: step.scopes,
        }),
      );
  }
}
