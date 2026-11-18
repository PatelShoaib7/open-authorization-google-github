import { Request, Response } from 'express';
import { HttpStatus } from '../../constants/index.js';
import { asyncHandler } from '../../utils/async-handler.js';
import { clearRefreshTokenCookie, clearSsoSessionCookie } from '../../utils/cookies.js';
import { UserService } from './user.service.js';

export class UserController {
  constructor(private readonly userService: UserService) {}

  public readonly getMe = asyncHandler(async (req: Request, res: Response) => {
    const authUser = req.user!;
    const profile = await this.userService.getMe(
      authUser.id,
      authUser.scopes,
      authUser.clientId,
    );
    res.status(HttpStatus.OK).json({
      success: true,
      data: profile,
    });
  });

  public readonly updateMe = asyncHandler(async (req: Request, res: Response) => {
    const authUser = req.user!;
    const updated = await this.userService.updateMe(authUser.id, req.body);
    res.status(HttpStatus.OK).json({
      success: true,
      data: updated,
    });
  });

  public readonly changePassword = asyncHandler(async (req: Request, res: Response) => {
    const authUser = req.user!;
    const { currentPassword, newPassword } = req.body as {
      currentPassword: string;
      newPassword: string;
    };
    await this.userService.changePassword(authUser.id, currentPassword, newPassword);
    clearRefreshTokenCookie(res);
    clearSsoSessionCookie(res);
    res.status(HttpStatus.OK).json({
      success: true,
      message: 'Password updated successfully. All active sessions have been revoked.',
    });
  });

  public readonly listMySessions = asyncHandler(async (req: Request, res: Response) => {
    const authUser = req.user!;
    const sessions = await this.userService.listMySessions(authUser.id);
    res.status(HttpStatus.OK).json({
      success: true,
      data: sessions,
    });
  });

  public readonly revokeMySession = asyncHandler(async (req: Request, res: Response) => {
    const authUser = req.user!;
    const familyId = req.params.familyId as string;
    await this.userService.revokeMySession(authUser.id, familyId);
    res.status(HttpStatus.OK).json({
      success: true,
      message: 'Session revoked.',
    });
  });

  public readonly listUsers = asyncHandler(async (_req: Request, res: Response) => {
    const users = await this.userService.listUsers();
    res.status(HttpStatus.OK).json({
      success: true,
      data: users,
    });
  });

  public readonly updateUserAccess = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.params.userId as string;
    const updated = await this.userService.updateUserAccess(userId, req.body);
    res.status(HttpStatus.OK).json({
      success: true,
      data: updated,
    });
  });
}
