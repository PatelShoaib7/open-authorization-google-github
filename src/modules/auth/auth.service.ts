import crypto from 'node:crypto';
import { env } from '../../config/env.js';
import {
  DEFAULT_CLIENT_SCOPES,
  ErrorCode,
  FIRST_PARTY_CLIENT_ID,
  HttpStatus,
  SocialProvider,
  UserRole,
} from '../../constants/index.js';
import { RequestMeta } from '../../types/index.js';
import { AppError } from '../../utils/app-error.js';
import { hashSecret, verifySecret } from '../../utils/crypto.js';
import { signAccessToken } from '../../utils/jwt.js';
import { UserEntity } from '../users/user.model.js';
import { IUserRepository } from '../users/user.repository.js';
import { PublicUserDto, toPublicUserDto } from '../users/user.service.js';
import { SocialOAuthService, VerifiedSocialProfile } from './social-oauth.service.js';
import { TokenFamilyService } from './token-family.service.js';

export interface AuthSessionBundle {
  user: PublicUserDto;
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  rawRefreshToken: string;
  rawSsoSessionToken: string;
}

export interface RegisterServiceInput {
  email: string;
  username: string;
  password: string;
  name: string;
}

let cachedDummyPasswordHash: string | null = null;
async function getDummyPasswordHash(): Promise<string> {
  if (!cachedDummyPasswordHash) {
    cachedDummyPasswordHash = await hashSecret('dummy-mitigation-secret-value-99!');
  }
  return cachedDummyPasswordHash;
}

export class AuthService {
  constructor(
    private readonly userRepository: IUserRepository,
    private readonly tokenFamilyService: TokenFamilyService,
    private readonly socialOAuthService: SocialOAuthService,
  ) {}

  public async register(
    input: RegisterServiceInput,
    meta?: RequestMeta,
  ): Promise<AuthSessionBundle> {
    const normalizedEmail = input.email.toLowerCase().trim();
    const normalizedUsername = input.username.toLowerCase().trim();

    const [existingEmail, existingUsername] = await Promise.all([
      this.userRepository.findByEmail(normalizedEmail),
      this.userRepository.findByUsername(normalizedUsername),
    ]);

    if (existingEmail) {
      throw new AppError(
        'An account with this email address already exists.',
        HttpStatus.CONFLICT,
        ErrorCode.DUPLICATE_RESOURCE,
      );
    }

    if (existingUsername) {
      throw new AppError(
        'This username is already taken.',
        HttpStatus.CONFLICT,
        ErrorCode.DUPLICATE_RESOURCE,
      );
    }

    const passwordHash = await hashSecret(input.password);
    const isAdminBootstrap = env.ADMIN_EMAILS.includes(normalizedEmail);
    const roles = isAdminBootstrap
      ? [UserRole.USER, UserRole.ADMIN]
      : [UserRole.USER];

    const createdUser = await this.userRepository.create({
      email: normalizedEmail,
      emailVerified: false,
      username: normalizedUsername,
      passwordHash,
      name: input.name.trim(),
      roles,
      scopes: [...DEFAULT_CLIENT_SCOPES],
    });

    return this.issueFirstPartySession(createdUser, meta);
  }

  public async login(
    identifier: string,
    password: string,
    meta?: RequestMeta,
  ): Promise<AuthSessionBundle> {
    const normalized = identifier.toLowerCase().trim();
    const user = normalized.includes('@')
      ? await this.userRepository.findByEmail(normalized, true)
      : await this.userRepository.findByUsername(normalized, true);

    if (!user || !user.passwordHash) {
      // Constant-work Argon2id verification mitigates timing-based user enumeration
      const dummyHash = await getDummyPasswordHash();
      await verifySecret(dummyHash, password);
      throw new AppError(
        'Invalid credentials.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.INVALID_CREDENTIALS,
      );
    }

    const isPasswordValid = await verifySecret(user.passwordHash, password);
    if (!isPasswordValid) {
      throw new AppError(
        'Invalid credentials.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.INVALID_CREDENTIALS,
      );
    }

    if (!user.isActive) {
      throw new AppError(
        'Account has been disabled.',
        HttpStatus.FORBIDDEN,
        ErrorCode.ACCOUNT_DISABLED,
      );
    }

    await this.userRepository.recordLogin(user.id);
    return this.issueFirstPartySession(user, meta);
  }

  public async refreshFirstPartySession(rawRefreshToken?: string): Promise<{
    accessToken: string;
    tokenType: 'Bearer';
    expiresIn: number;
    newRawRefreshToken: string;
    user: PublicUserDto;
  }> {
    if (!rawRefreshToken) {
      throw new AppError(
        'Missing refresh token cookie.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.INVALID_REFRESH_TOKEN,
      );
    }

    const { newRawRefreshToken, family } =
      await this.tokenFamilyService.rotateRefreshToken(rawRefreshToken);

    const user = await this.userRepository.findById(family.userId);
    if (!user || !user.isActive) {
      await this.tokenFamilyService.revokeFamilyById(family.familyId);
      throw new AppError(
        'User account associated with session is inactive or deleted.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.ACCOUNT_DISABLED,
      );
    }

    const grantedScopes = family.scope
      .split(' ')
      .filter((s) => s.length > 0);

    const { accessToken, expiresIn } = signAccessToken({
      userId: user.id,
      clientId: family.clientId,
      roles: user.roles,
      scopes: grantedScopes,
    });

    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn,
      newRawRefreshToken,
      user: toPublicUserDto(user, grantedScopes, family.clientId),
    };
  }

  public async logout(
    rawRefreshToken?: string,
    rawSsoSessionToken?: string,
  ): Promise<void> {
    await Promise.all([
      this.tokenFamilyService.revokeFamilyByRawToken(rawRefreshToken),
      this.tokenFamilyService.destroySsoSession(rawSsoSessionToken),
    ]);
  }

  public async logoutAllDevices(userId: string): Promise<number> {
    const [revokedCount] = await Promise.all([
      this.tokenFamilyService.revokeAllUserFamilies(userId),
      this.tokenFamilyService.destroyAllUserSsoSessions(userId),
    ]);
    return revokedCount;
  }

  public async initiateSocialLogin(
    provider: SocialProvider,
    authReqId?: string,
  ): Promise<string> {
    return this.socialOAuthService.createAuthorizationRedirectUrl(provider, authReqId);
  }

  public async completeSocialLogin(
    provider: SocialProvider,
    code: string,
    state: string,
    meta?: RequestMeta,
  ): Promise<{ session: AuthSessionBundle; authReqId?: string }> {
    const { profile, authReqId } =
      await this.socialOAuthService.verifyCallbackAndFetchProfile(provider, code, state);

    const user = await this.upsertUserFromSocialProfile(profile);
    if (!user.isActive) {
      throw new AppError(
        'Account has been disabled.',
        HttpStatus.FORBIDDEN,
        ErrorCode.ACCOUNT_DISABLED,
      );
    }

    const session = await this.issueFirstPartySession(user, meta);
    return {
      session,
      ...(authReqId ? { authReqId } : {}),
    };
  }

  private async upsertUserFromSocialProfile(
    profile: VerifiedSocialProfile,
  ): Promise<UserEntity> {
    const providerField =
      profile.provider === SocialProvider.GOOGLE ? 'googleId' : 'githubId';

    const existingByProvider = await this.userRepository.findByProviderId(
      providerField,
      profile.providerUserId,
    );

    if (existingByProvider) {
      await this.userRepository.recordLogin(existingByProvider.id);
      return existingByProvider;
    }

    const existingByEmail = await this.userRepository.findByEmail(profile.email);
    if (existingByEmail) {
      if (!profile.emailVerified) {
        throw new AppError(
          'Cannot link social account with an unverified email to an existing account.',
          HttpStatus.FORBIDDEN,
          ErrorCode.SOCIAL_AUTH_FAILED,
        );
      }

      const linked = await this.userRepository.linkProvider(
        existingByEmail.id,
        providerField,
        profile.providerUserId,
        true,
        existingByEmail.avatarUrl ?? profile.avatarUrl,
      );
      return linked ?? existingByEmail;
    }

    const uniqueUsername = await this.generateAvailableUsername(profile.preferredUsername);
    const isAdminBootstrap =
      profile.emailVerified && env.ADMIN_EMAILS.includes(profile.email);

    return this.userRepository.create({
      email: profile.email,
      emailVerified: profile.emailVerified,
      username: uniqueUsername,
      name: profile.name,
      ...(profile.avatarUrl ? { avatarUrl: profile.avatarUrl } : {}),
      ...(profile.bio ? { bio: profile.bio } : {}),
      ...(profile.location ? { location: profile.location } : {}),
      roles: isAdminBootstrap ? [UserRole.USER, UserRole.ADMIN] : [UserRole.USER],
      scopes: [...DEFAULT_CLIENT_SCOPES],
      providers: {
        [providerField]: profile.providerUserId,
      },
    });
  }

  private async generateAvailableUsername(base: string): Promise<string> {
    const sanitized = base.replace(/[^a-z0-9_-]/gi, '').toLowerCase().slice(0, 30);
    const candidateBase = sanitized.length >= 3 ? sanitized : `user_${sanitized}`;

    const existing = await this.userRepository.findByUsername(candidateBase);
    if (!existing) {
      return candidateBase;
    }

    const suffix = crypto.randomBytes(3).toString('hex');
    return `${candidateBase}_${suffix}`;
  }

  private async issueFirstPartySession(
    user: UserEntity,
    meta?: RequestMeta,
  ): Promise<AuthSessionBundle> {
    const scopes = Array.from(new Set([...DEFAULT_CLIENT_SCOPES, ...user.scopes]));
    const scopeStr = scopes.join(' ');

    const { accessToken, expiresIn } = signAccessToken({
      userId: user.id,
      clientId: FIRST_PARTY_CLIENT_ID,
      roles: user.roles,
      scopes,
    });

    const [{ rawRefreshToken }, rawSsoSessionToken] = await Promise.all([
      this.tokenFamilyService.issueRefreshTokenFamily({
        userId: user.id,
        clientId: FIRST_PARTY_CLIENT_ID,
        scope: scopeStr,
        meta,
      }),
      this.tokenFamilyService.createSsoSession(user.id, meta),
    ]);

    return {
      user: toPublicUserDto(user, scopes, FIRST_PARTY_CLIENT_ID),
      accessToken,
      tokenType: 'Bearer',
      expiresIn,
      rawRefreshToken,
      rawSsoSessionToken,
    };
  }
}
