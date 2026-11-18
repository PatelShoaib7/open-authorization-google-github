import { Request, Response } from 'express';
import {
  COOKIE_NAMES,
  ErrorCode,
  HttpStatus,
  SocialProvider,
} from '../../constants/index.js';
import { RequestMeta } from '../../types/index.js';
import { asyncHandler } from '../../utils/async-handler.js';
import {
  clearRefreshTokenCookie,
  clearSsoSessionCookie,
  setRefreshTokenCookie,
  setSsoSessionCookie,
} from '../../utils/cookies.js';
import { AuthService } from './auth.service.js';

function extractRequestMeta(req: Request): RequestMeta {
  return {
    ipAddress: req.ip,
    userAgent: req.header('User-Agent'),
  };
}

export class AuthController {
  constructor(private readonly authService: AuthService) {}

  public readonly register = asyncHandler(async (req: Request, res: Response) => {
    const session = await this.authService.register(req.body, extractRequestMeta(req));

    setRefreshTokenCookie(res, session.rawRefreshToken);
    setSsoSessionCookie(res, session.rawSsoSessionToken);

    res.status(HttpStatus.CREATED).json({
      success: true,
      data: {
        user: session.user,
        accessToken: session.accessToken,
        tokenType: session.tokenType,
        expiresIn: session.expiresIn,
      },
    });
  });

  public readonly login = asyncHandler(async (req: Request, res: Response) => {
    const { identifier, password, authReqId } = req.body as {
      identifier: string;
      password: string;
      authReqId?: string;
    };

    const session = await this.authService.login(
      identifier,
      password,
      extractRequestMeta(req),
    );

    setRefreshTokenCookie(res, session.rawRefreshToken);
    setSsoSessionCookie(res, session.rawSsoSessionToken);

    // If login was submitted via HTML form during an /oauth/authorize SSO transaction, resume OAuth flow
    const acceptsHtml = (req.header('Accept') ?? '').includes('text/html');
    if (authReqId && acceptsHtml) {
      res.redirect(
        HttpStatus.FOUND,
        `/oauth/authorize/resume?auth_req_id=${encodeURIComponent(authReqId)}`,
      );
      return;
    }

    res.status(HttpStatus.OK).json({
      success: true,
      data: {
        user: session.user,
        accessToken: session.accessToken,
        tokenType: session.tokenType,
        expiresIn: session.expiresIn,
        ...(authReqId
          ? {
              resumeAuthorizeUrl: `/oauth/authorize/resume?auth_req_id=${encodeURIComponent(authReqId)}`,
            }
          : {}),
      },
    });
  });

  public readonly refresh = asyncHandler(async (req: Request, res: Response) => {
    const rawRefreshToken = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN] as
      | string
      | undefined;

    try {
      const rotated = await this.authService.refreshFirstPartySession(rawRefreshToken);
      setRefreshTokenCookie(res, rotated.newRawRefreshToken);
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');

      res.status(HttpStatus.OK).json({
        success: true,
        data: {
          accessToken: rotated.accessToken,
          tokenType: rotated.tokenType,
          expiresIn: rotated.expiresIn,
          user: rotated.user,
        },
      });
    } catch (err) {
      clearRefreshTokenCookie(res);
      if (
        err instanceof Error &&
        'code' in err &&
        err.code === ErrorCode.REFRESH_TOKEN_REUSE_DETECTED
      ) {
        clearSsoSessionCookie(res);
      }
      throw err;
    }
  });

  public readonly logout = asyncHandler(async (req: Request, res: Response) => {
    const rawRefreshToken = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN] as
      | string
      | undefined;
    const rawSsoToken = req.cookies?.[COOKIE_NAMES.SSO_SESSION] as string | undefined;

    await this.authService.logout(rawRefreshToken, rawSsoToken);
    clearRefreshTokenCookie(res);
    clearSsoSessionCookie(res);

    res.status(HttpStatus.OK).json({
      success: true,
      message: 'Logged out successfully.',
    });
  });

  public readonly logoutAll = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user!.id;
    const revokedFamilies = await this.authService.logoutAllDevices(userId);
    clearRefreshTokenCookie(res);
    clearSsoSessionCookie(res);

    res.status(HttpStatus.OK).json({
      success: true,
      message: 'All sessions across devices and clients have been revoked.',
      data: { revokedSessions: revokedFamilies },
    });
  });

  public readonly googleRedirect = asyncHandler(async (req: Request, res: Response) => {
    const authReqId = req.query.auth_req_id as string | undefined;
    const url = await this.authService.initiateSocialLogin(
      SocialProvider.GOOGLE,
      authReqId,
    );
    res.redirect(HttpStatus.FOUND, url);
  });

  public readonly googleCallback = asyncHandler(async (req: Request, res: Response) => {
    const { code, state } = req.query as { code: string; state: string };
    const { session, authReqId } = await this.authService.completeSocialLogin(
      SocialProvider.GOOGLE,
      code,
      state,
      extractRequestMeta(req),
    );

    setRefreshTokenCookie(res, session.rawRefreshToken);
    setSsoSessionCookie(res, session.rawSsoSessionToken);

    if (authReqId) {
      res.redirect(
        HttpStatus.FOUND,
        `/oauth/authorize/resume?auth_req_id=${encodeURIComponent(authReqId)}`,
      );
      return;
    }

    res.status(HttpStatus.OK).json({
      success: true,
      data: {
        user: session.user,
        accessToken: session.accessToken,
        tokenType: session.tokenType,
        expiresIn: session.expiresIn,
      },
    });
  });

  public readonly githubRedirect = asyncHandler(async (req: Request, res: Response) => {
    const authReqId = req.query.auth_req_id as string | undefined;
    const url = await this.authService.initiateSocialLogin(
      SocialProvider.GITHUB,
      authReqId,
    );
    res.redirect(HttpStatus.FOUND, url);
  });

  public readonly githubCallback = asyncHandler(async (req: Request, res: Response) => {
    const { code, state } = req.query as { code: string; state: string };
    const { session, authReqId } = await this.authService.completeSocialLogin(
      SocialProvider.GITHUB,
      code,
      state,
      extractRequestMeta(req),
    );

    setRefreshTokenCookie(res, session.rawRefreshToken);
    setSsoSessionCookie(res, session.rawSsoSessionToken);

    if (authReqId) {
      res.redirect(
        HttpStatus.FOUND,
        `/oauth/authorize/resume?auth_req_id=${encodeURIComponent(authReqId)}`,
      );
      return;
    }

    res.status(HttpStatus.OK).json({
      success: true,
      data: {
        user: session.user,
        accessToken: session.accessToken,
        tokenType: session.tokenType,
        expiresIn: session.expiresIn,
      },
    });
  });
}
