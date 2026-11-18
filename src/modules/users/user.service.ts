import {
  ErrorCode,
  FIRST_PARTY_CLIENT_ID,
  HttpStatus,
  OAuthScope,
} from '../../constants/index.js';
import { AppError } from '../../utils/app-error.js';
import { hashSecret, verifySecret } from '../../utils/crypto.js';
import { SafeSessionSummary, TokenFamilyService } from '../auth/token-family.service.js';
import { UserEntity } from './user.model.js';
import {
  IUserRepository,
  UpdateUserAccessInput,
  UpdateUserProfileInput,
} from './user.repository.js';

export interface PublicUserDto {
  id: string;
  sub: string;
  username?: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  avatarUrl?: string;
  bio?: string;
  location?: string;
  roles: string[];
  scopes: string[];
  linkedProviders: string[];
  isActive: boolean;
  lastLoginAt?: string;
  createdAt: string;
}

export function toPublicUserDto(user: UserEntity, grantedScopes?: string[], clientId?: string): PublicUserDto {
  const isFirstParty = !clientId || clientId === FIRST_PARTY_CLIENT_ID;
  const includeProfile =
    isFirstParty || !grantedScopes || grantedScopes.includes(OAuthScope.PROFILE);
  const includeEmail =
    isFirstParty || !grantedScopes || grantedScopes.includes(OAuthScope.EMAIL);

  const linkedProviders: string[] = [];
  if (user.providers.googleId) linkedProviders.push('google');
  if (user.providers.githubId) linkedProviders.push('github');

  return {
    id: user.id,
    sub: user.id,
    ...(includeProfile
      ? {
          username: user.username,
          name: user.name,
          ...(user.avatarUrl ? { avatarUrl: user.avatarUrl } : {}),
          ...(user.bio ? { bio: user.bio } : {}),
          ...(user.location ? { location: user.location } : {}),
        }
      : {}),
    ...(includeEmail
      ? {
          email: user.email,
          emailVerified: user.emailVerified,
        }
      : {}),
    roles: user.roles,
    scopes: user.scopes,
    linkedProviders,
    isActive: user.isActive,
    ...(user.lastLoginAt ? { lastLoginAt: user.lastLoginAt.toISOString() } : {}),
    createdAt: user.createdAt.toISOString(),
  };
}

export class UserService {
  constructor(
    private readonly userRepository: IUserRepository,
    private readonly tokenFamilyService: TokenFamilyService,
  ) {}

  public async getMe(
    userId: string,
    grantedScopes: string[],
    clientId: string,
  ): Promise<PublicUserDto> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new AppError(
        'Authenticated user record no longer exists.',
        HttpStatus.NOT_FOUND,
        ErrorCode.RESOURCE_NOT_FOUND,
      );
    }
    if (!user.isActive) {
      throw new AppError(
        'Account has been disabled.',
        HttpStatus.FORBIDDEN,
        ErrorCode.ACCOUNT_DISABLED,
      );
    }
    return toPublicUserDto(user, grantedScopes, clientId);
  }

  public async updateMe(userId: string, input: UpdateUserProfileInput): Promise<PublicUserDto> {
    const updated = await this.userRepository.updateProfile(userId, input);
    if (!updated) {
      throw new AppError(
        'User not found.',
        HttpStatus.NOT_FOUND,
        ErrorCode.RESOURCE_NOT_FOUND,
      );
    }
    return toPublicUserDto(updated);
  }

  public async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.userRepository.findById(userId, true);
    if (!user) {
      throw new AppError(
        'User not found.',
        HttpStatus.NOT_FOUND,
        ErrorCode.RESOURCE_NOT_FOUND,
      );
    }

    if (!user.passwordHash) {
      throw new AppError(
        'This account uses passwordless social login and has no password set.',
        HttpStatus.BAD_REQUEST,
        ErrorCode.INVALID_CREDENTIALS,
      );
    }

    const isValidCurrent = await verifySecret(user.passwordHash, currentPassword);
    if (!isValidCurrent) {
      throw new AppError(
        'Current password is incorrect.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.INVALID_CREDENTIALS,
      );
    }

    const newHash = await hashSecret(newPassword);
    await this.userRepository.updatePassword(userId, newHash);

    // Security hardening: revoke all refresh token families and SSO sessions upon password rotation
    await this.tokenFamilyService.revokeAllUserFamilies(userId);
    await this.tokenFamilyService.destroyAllUserSsoSessions(userId);
  }

  public async listMySessions(userId: string): Promise<SafeSessionSummary[]> {
    return this.tokenFamilyService.listUserActiveFamilies(userId);
  }

  public async revokeMySession(userId: string, familyId: string): Promise<void> {
    const revoked = await this.tokenFamilyService.revokeFamilyById(familyId, userId);
    if (!revoked) {
      throw new AppError(
        'Active session not found.',
        HttpStatus.NOT_FOUND,
        ErrorCode.RESOURCE_NOT_FOUND,
      );
    }
  }

  public async listUsers(limit = 50, skip = 0): Promise<PublicUserDto[]> {
    const users = await this.userRepository.listAll(limit, skip);
    return users.map((u) => toPublicUserDto(u));
  }

  public async updateUserAccess(
    targetUserId: string,
    input: UpdateUserAccessInput,
  ): Promise<PublicUserDto> {
    const updated = await this.userRepository.updateAccess(targetUserId, input);
    if (!updated) {
      throw new AppError(
        'Target user not found.',
        HttpStatus.NOT_FOUND,
        ErrorCode.RESOURCE_NOT_FOUND,
      );
    }

    if (input.isActive === false) {
      await this.tokenFamilyService.revokeAllUserFamilies(targetUserId);
      await this.tokenFamilyService.destroyAllUserSsoSessions(targetUserId);
    }

    return toPublicUserDto(updated);
  }
}
